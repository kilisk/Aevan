//! `aevan login` — stage 2, exactly one authentication attempt.
//!
//! Credential collection lives here (TTY or redirected stdin); the exchange
//! itself is [`aevan_daemon::auth`], shared with the daemon and foreground
//! connect. Password and token are never accepted in argv or the environment
//! and are never printed.

use serde::Serialize;
use zeroize::Zeroizing;

use aevan_core::{AevanError, AevanResult, Profile, RealmSource};
pub use aevan_daemon::auth::LoginSession;
use aevan_daemon::auth::{self, AuthCredentials};

use crate::{common, tty};

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    outcome: &'static str,
    status_code: u16,
    redirected: bool,
    ncp_config_present: bool,
    token_submitted: bool,
    realm: String,
    realm_source: &'static str,
}

/// Run the login command.
pub fn run(profile_name: Option<&str>, token_stdin: bool, json: bool) -> AevanResult<()> {
    let (profile, source) = common::select_profile_with_realm(profile_name)?;
    let session = authenticate_profile(&profile, token_stdin)?;
    report_detected_realm(&profile, source, json);

    match &session.outcome {
        aevan_nc::LoginOutcome::Success {
            status_code,
            location,
        } => {
            // oNCP configuration is exchanged in the binary handshake after the
            // HTTP login, not in this response body (M2).
            let ncp_config_present = false;
            let report = Report {
                schema_version: common::SCHEMA_VERSION,
                outcome: "success",
                status_code: *status_code,
                redirected: location.is_some(),
                ncp_config_present,
                token_submitted: session.token_submitted,
                realm: profile.realm.clone(),
                realm_source: realm_source_label(source),
            };
            if json {
                let text = serde_json::to_string_pretty(&report).map_err(|error| {
                    AevanError::Config(format!("cannot serialise login output: {error}"))
                })?;
                println!("{text}");
            } else {
                println!(
                    "login: success (HTTP {status_code}; redirect {}; NCP config {}; token {})",
                    if report.redirected { "yes" } else { "no" },
                    if ncp_config_present {
                        "cached"
                    } else {
                        "not present"
                    },
                    if session.token_submitted {
                        "submitted"
                    } else {
                        "not required"
                    }
                );
            }
            Ok(())
        }
        other => Err(AevanError::Unsupported(format!(
            "login did not succeed: {other:?}"
        ))),
    }
}

fn report_detected_realm(profile: &Profile, source: RealmSource, json: bool) {
    if source.is_detected() && !json {
        println!("realm: {} (detected)", profile.realm);
    }
}

fn realm_source_label(source: RealmSource) -> &'static str {
    match source {
        RealmSource::Configured => "configured",
        RealmSource::Detected => "detected",
    }
}

/// Authenticate an already selected profile with exactly one attempt.
pub fn authenticate_profile(profile: &Profile, token_stdin: bool) -> AevanResult<LoginSession> {
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

    // A token may be supplied up front. When stdin is not a terminal this is the
    // second newline-delimited value after the password.
    let token = if token_stdin {
        let value = tty::read_secret("Token: ")?;
        if value.is_empty() {
            None
        } else {
            Some(Zeroizing::new(value))
        }
    } else {
        None
    };

    auth::authenticate(
        profile,
        AuthCredentials::new(username, password, token),
        || {
            if tty::stdin_is_terminal() {
                let value = tty::read_secret("Token: ")?;
                Ok(if value.is_empty() {
                    None
                } else {
                    Some(Zeroizing::new(value))
                })
            } else {
                Ok(None)
            }
        },
    )
}
