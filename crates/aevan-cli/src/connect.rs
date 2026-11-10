//! `aevan connect` — daemon by default, in-process with `--foreground`.
//!
//! Both paths use the shared orchestration in `aevan-daemon`: one credential
//! attempt, one oNCP handshake, a journal written before the first change,
//! apply, the ESP loop and teardown. The default path adds the local control
//! socket so `status`, `disconnect` and `logs` see the same session.

use serde::Serialize;
use zeroize::Zeroizing;

use aevan_core::{AevanError, AevanResult, Profile, RealmSource};
use aevan_daemon::client::{self, ClientError};
use aevan_daemon::connector::{self, ApplyPlan, ConnectOptions, ConnectionInfo, TunnelControl};
use aevan_daemon::{journal, Request, SecretString};

use crate::{common, login, tty};

#[derive(Clone, Copy)]
struct ConnectFlags {
    token_stdin: bool,
    foreground: bool,
    no_daemon: bool,
    dry_run: bool,
    json: bool,
}

/// Run `aevan connect`.
pub fn run(
    profile_name: Option<&str>,
    token_stdin: bool,
    foreground: bool,
    no_daemon: bool,
    dry_run: bool,
    json: bool,
) -> AevanResult<()> {
    let flags = ConnectFlags {
        token_stdin,
        foreground,
        no_daemon,
        dry_run,
        json,
    };
    // A dry run changes nothing and must not leave a tunnel behind, so it stays
    // in this process even when the daemon is the default path.
    if flags.foreground || flags.no_daemon || flags.dry_run {
        run_foreground(profile_name, &flags)
    } else {
        via_daemon(profile_name, &flags)
    }
}

fn run_foreground(profile_name: Option<&str>, flags: &ConnectFlags) -> AevanResult<()> {
    let (profile, source) = common::select_profile_with_realm(profile_name)?;
    announce_detected_realm(&profile, source, flags.json);
    let mut session = login::authenticate_profile(&profile, flags.token_stdin)?;

    let control = ForegroundControl {
        json: flags.json,
        profile: profile.name.clone(),
    };
    let config_dir = aevan_core::paths::config_dir()?;
    let journal_path = journal::journal_path(&config_dir);
    aevan_tun::platform::install_shutdown_handler();
    connector::connect_session(
        &profile,
        &mut session,
        &control,
        ConnectOptions {
            dry_run: flags.dry_run,
        },
        Some(&journal_path),
    )
}

fn via_daemon(profile_name: Option<&str>, flags: &ConnectFlags) -> AevanResult<()> {
    let (profile, source) = common::select_profile_with_realm(profile_name)?;
    announce_detected_realm(&profile, source, flags.json);
    let username = match profile.username.clone() {
        Some(username) => username,
        None if tty::stdin_is_terminal() => {
            let username = tty::read_visible("Username: ")?;
            if username.is_empty() {
                return Err(AevanError::Config("username must not be empty".into()));
            }
            username
        }
        None => {
            return Err(AevanError::Config(
                "profile has no username and stdin is not a terminal".into(),
            ))
        }
    };

    let password = tty::read_secret("Password: ")?;
    if password.is_empty() {
        return Err(AevanError::Config("password must not be empty".into()));
    }
    let password = Zeroizing::new(password);

    // The daemon cannot prompt: a token challenge becomes exit 2 unless the
    // token was supplied with the request. Read it up front from stdin or the
    // terminal; an empty value means "not required".
    let token = if flags.token_stdin {
        let value = tty::read_secret("Token: ")?;
        if value.is_empty() {
            None
        } else {
            Some(Zeroizing::new(value))
        }
    } else if tty::stdin_is_terminal() {
        let value = tty::read_secret("Token (leave empty if not required): ")?;
        if value.is_empty() {
            None
        } else {
            Some(Zeroizing::new(value))
        }
    } else {
        None
    };

    let request = connect_request(&profile, username, password, token);

    // The daemon stays a deliberate, visible thing: only `aevan` with no
    // subcommand starts it implicitly. `aevan connect` reports the reach failure
    // so the operator decides when and how to elevate.
    let answer = client::request_with_endpoint(&request, None).map_err(ClientError::into_aevan)?;

    if !answer.response.ok {
        return Err(answer.response.into_error());
    }
    let status = answer.response.status.unwrap_or_default();
    common::print_status(&status, flags.json, &answer.endpoint);
    Ok(())
}

/// Print the detected realm once, before the tunnel starts.
fn announce_detected_realm(profile: &Profile, source: RealmSource, json: bool) {
    if source.is_detected() && !json {
        println!("realm: {} (detected)", profile.realm);
    }
}

/// Build the version-2 connect request from the locally resolved profile.
///
/// The CLI owns profile resolution; the daemon receives only the connection
/// parameters it needs, so a root daemon never reads this user's store.
fn connect_request(
    profile: &Profile,
    username: String,
    password: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
) -> Request {
    Request::connect(
        Some(profile.name.clone()),
        Some(profile.url.clone()),
        Some(profile.realm.clone()),
        username,
        SecretString::new(password.as_str().to_owned()),
        token.map(|token| SecretString::new(token.as_str().to_owned())),
    )
}

struct ForegroundControl {
    json: bool,
    profile: String,
}

impl TunnelControl for ForegroundControl {
    fn should_stop(&self) -> bool {
        aevan_tun::platform::shutdown_requested()
    }

    fn planned(&self, plan: &ApplyPlan) {
        if let Err(error) = print_dry_run(plan, &self.profile) {
            eprintln!("aevan: {error}");
        }
    }

    fn connected(&self, info: &ConnectionInfo) {
        print_connected(info, self.json);
    }
}

#[derive(Debug, Serialize)]
struct DryRunReport<'a> {
    schema_version: u32,
    dry_run: bool,
    profile: &'a str,
    device: &'a str,
    address: Option<String>,
    prefix_len: Option<u8>,
    mtu: Option<u16>,
    routes: Vec<DryRunRoute>,
    dns: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DryRunRoute {
    destination: String,
    prefix_len: u8,
    gateway: Option<String>,
    metric: u32,
}

fn print_dry_run(plan: &ApplyPlan, profile: &str) -> AevanResult<()> {
    let report = DryRunReport {
        schema_version: common::SCHEMA_VERSION,
        dry_run: true,
        profile,
        device: &plan.device,
        address: plan.address.map(|address| address.to_string()),
        prefix_len: plan.address.map(|_| plan.prefix_len),
        mtu: plan.mtu,
        routes: plan
            .routes
            .iter()
            .map(|route| DryRunRoute {
                destination: route.destination.to_string(),
                prefix_len: route.prefix_len,
                gateway: route.gateway.map(|gateway| gateway.to_string()),
                metric: route.metric,
            })
            .collect(),
        dns: plan.dns.iter().map(ToString::to_string).collect(),
    };

    let text = serde_json::to_string_pretty(&report).map_err(|error| {
        AevanError::Config(format!("cannot serialise the connect plan: {error}"))
    })?;
    println!("{text}");
    tracing::info!("dry run: no device or route was changed");
    Ok(())
}

fn print_connected(info: &ConnectionInfo, json: bool) {
    let dns = info.dns.iter().map(ToString::to_string).collect::<Vec<_>>();
    if json {
        #[derive(Serialize)]
        struct Report<'a> {
            schema_version: u32,
            connected: bool,
            profile: &'a str,
            device: &'a str,
            address: Option<String>,
            prefix_len: Option<u8>,
            mtu: Option<u16>,
            route_count: usize,
            dns: Vec<String>,
        }
        let report = Report {
            schema_version: common::SCHEMA_VERSION,
            connected: true,
            profile: &info.profile,
            device: &info.device,
            address: info.address.map(|address| address.to_string()),
            prefix_len: info.address.map(|_| info.prefix_len),
            mtu: info.mtu,
            route_count: info.route_count,
            dns,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => eprintln!("aevan: cannot serialise the connected summary: {error}"),
        }
    } else {
        let address = info
            .address
            .map(|address| format!("{address}/{}", info.prefix_len))
            .unwrap_or_else(|| "no address".to_owned());
        println!(
            "connected: {address} on {} (MTU {})",
            info.device,
            info.mtu
                .map(|mtu| mtu.to_string())
                .unwrap_or_else(|| "default".to_owned())
        );
        println!(
            "  routes: {}  dns: {}",
            info.route_count,
            if dns.is_empty() {
                "none".to_owned()
            } else {
                dns.join(", ")
            }
        );
    }
    tracing::info!("ESP data plane running; press Ctrl+C to disconnect");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_connect_request_carries_what_the_profile_holds() {
        let profile = Profile::new(
            "example",
            "https://vpn.example.net/example_realm",
            "example_realm",
        )
        .expect("profile");

        let request = connect_request(
            &profile,
            "example_user".into(),
            Zeroizing::new("hunter2".into()),
            None,
        );

        assert_eq!(request.schema_version, aevan_daemon::SCHEMA_VERSION);
        assert_eq!(request.command, "connect");
        assert_eq!(request.profile.as_deref(), Some("example"));
        assert_eq!(request.gateway_url.as_deref(), Some(profile.url.as_str()));
        assert_eq!(request.realm.as_deref(), Some(profile.realm.as_str()));
        assert_eq!(request.username.as_deref(), Some("example_user"));
        assert_eq!(
            request.password.as_ref().map(SecretString::expose),
            Some("hunter2")
        );
    }
}
