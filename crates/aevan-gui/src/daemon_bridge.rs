//! Blocking control-client calls used from GUI worker threads.
//!
//! All tunnel work goes through `aevan-daemon`'s control client. This module
//! resolves the selected profile from the user's own store before a connect,
//! but never opens a TLS connection, reads secret material or touches the
//! adapter/routes/DNS.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aevan_core::{Profile, ProfileStore};
use aevan_daemon::autostart::{self, TaskState};
use aevan_daemon::client::{self, ClientError};
use aevan_daemon::elevate::{self, StartOutcome};
use aevan_daemon::{Request, Response, StatusReport};

use crate::view_model::{totp_account, ConnectCredentials, TotpEnrolment, KEYRING_SERVICE};

const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const DAEMON_WAIT: Duration = Duration::from_secs(10);
const AUTOSTART_WAIT: Duration = Duration::from_secs(10);

/// The daemon endpoint shown in settings and reach-failure messages.
pub fn endpoint() -> String {
    aevan_daemon::server::endpoint_description()
}

/// Poll `status` once and report which candidate endpoint answered.
pub fn status() -> Result<(StatusReport, String), ClientError> {
    let answer = client::request_with_endpoint(&Request::status(), Some(STATUS_TIMEOUT))?;
    Ok((expect_status(answer.response)?, answer.endpoint))
}

/// Submit exactly one `connect` request.
///
/// There is no read timeout, matching the CLI: the daemon returns when the
/// single authentication attempt and the apply step have finished.
pub fn connect(credentials: ConnectCredentials) -> Result<StatusReport, ClientError> {
    let profile = local_profile(credentials.profile_name())?;
    let request = credentials.into_request(&profile.url, &profile.realm);
    let response = client::request(&request, None)?;
    expect_status(response)
}

/// Resolve a profile from this user's store before talking to the daemon.
///
/// The daemon may run as root with a different (empty) store, so sending a
/// name alone would fail there.
fn local_profile(name: &str) -> Result<Profile, ClientError> {
    let path = ProfileStore::default_path().map_err(|error| {
        ClientError::Transport(format!("cannot resolve the local profile store: {error}"))
    })?;
    let store = ProfileStore::load(&path).map_err(|error| {
        ClientError::Transport(format!(
            "cannot read the local profile store {}: {error}",
            path.display()
        ))
    })?;
    store.get(name).cloned().ok_or_else(|| {
        ClientError::Transport(format!(
            "profile '{name}' was not found in {}; add it before connecting",
            path.display()
        ))
    })
}

/// Submit one `disconnect` request.
pub fn disconnect(profile: Option<String>) -> Result<StatusReport, ClientError> {
    let request = Request::disconnect(profile, false);
    let response = client::request(&request, Some(DISCONNECT_TIMEOUT))?;
    expect_status(response)
}

/// Retry crash recovery through the daemon (`aevan reset`).
pub fn recover() -> Result<StatusReport, ClientError> {
    let response = client::request(&Request::recover(), Some(DISCONNECT_TIMEOUT))?;
    expect_status(response)
}

/// Read and decode the TOTP secret for a profile from the OS keyring.
///
/// A missing entry and an unavailable backend both mean "no TOTP enrolled".
/// This function never logs or returns the encoded secret.
pub fn totp_secret(profile: &str) -> Option<Vec<u8>> {
    use aevan_secrets::{decode_base32, KeyringStore, SecretStore};

    let store = KeyringStore::new();
    let account = totp_account(profile);
    match store.get(KEYRING_SERVICE, &account) {
        Ok(Some(secret)) => decode_base32(secret.expose()).ok(),
        _ => None,
    }
}

/// Write a validated TOTP secret to the OS keyring.
///
/// This is the only path the GUI uses to write secret material, and it writes
/// only to the keyring. The returned decoded bytes feed the live countdown; the
/// normalized base32 text is not kept in the view model afterwards.
pub fn save_totp_secret(enrolment: TotpEnrolment) -> Result<(String, Vec<u8>), String> {
    use aevan_secrets::{KeyringStore, Secret, SecretStore};

    let profile = enrolment.profile().to_owned();
    let mut store = KeyringStore::new();
    store
        .set(
            KEYRING_SERVICE,
            &totp_account(&profile),
            Secret::new(enrolment.encoded().to_owned()),
        )
        .map_err(|error| error.to_string())?;
    Ok((profile, enrolment.into_decoded()))
}

/// Remove a profile's TOTP secret from the OS keyring.
pub fn remove_totp_secret(profile: &str) -> Result<(), String> {
    use aevan_secrets::{KeyringStore, SecretStore};

    let mut store = KeyringStore::new();
    store
        .delete(KEYRING_SERVICE, &totp_account(profile))
        .map_err(|error| error.to_string())
}

/// Start `aevand` beside this GUI, then wait for the control endpoint.
///
/// macOS installs the system LaunchDaemon once (one native prompt) and reuses
/// it afterwards; Windows keeps the single UAC elevation. Nothing is started
/// silently: this is only called by the explicit start action.
pub fn start_daemon() -> Result<(), String> {
    let executable = daemon_binary()?;
    start_daemon_beside(&executable).map_err(|message| {
        crate::start_log::with_tail(
            message,
            crate::start_log::tail_default(crate::start_log::BANNER_LINES),
        )
    })
}

#[cfg(target_os = "macos")]
fn start_daemon_beside(executable: &Path) -> Result<(), String> {
    use aevan_daemon::launchd;

    use crate::relaunch::{self, RelaunchOps};
    use crate::start_log;

    struct MacOps<'a> {
        executable: &'a Path,
    }

    fn record(outcome: &aevan_daemon::elevate::ScriptOutcome) {
        let _ = start_log::record_default(&outcome.command, outcome.exit_status, &outcome.stderr);
    }

    fn prompted_outcome(outcome: StartOutcome, action: &str) -> Result<(), String> {
        match outcome {
            StartOutcome::Started => Ok(()),
            StartOutcome::Cancelled => Err(format!(
                "{action} needs administrator approval; the prompt was dismissed"
            )),
            StartOutcome::Failed(message) => Err(message),
        }
    }

    impl RelaunchOps for MacOps<'_> {
        fn socket_answers(&self) -> bool {
            client::request(&Request::status(), Some(STATUS_TIMEOUT)).is_ok()
        }

        fn daemon_installed(&self) -> bool {
            launchd::is_installed()
        }

        fn kickstart(&self) -> Result<(), String> {
            launchd::kickstart()
        }

        fn kickstart_elevated(&self) -> Result<(), String> {
            let outcome = launchd::rearm_detailed();
            record(&outcome);
            prompted_outcome(outcome.outcome, "starting the Aevan daemon")
        }

        fn install_elevated(&self) -> Result<(), String> {
            let outcome = launchd::install_detailed(self.executable);
            record(&outcome);
            prompted_outcome(outcome.outcome, "installing the Aevan daemon")
        }

        fn wait_ready(&self) -> Result<(), String> {
            client::wait_for_daemon(DAEMON_WAIT)
                .map_err(|error| format!("the daemon did not answer within 10 seconds: {error}"))
        }
    }

    let report = relaunch::relaunch(&MacOps { executable })?;
    tracing::info!(
        method = ?report.method,
        prompted = report.prompted,
        "daemon start finished"
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn start_daemon_beside(executable: &Path) -> Result<(), String> {
    match elevate::start_elevated(executable, &[]) {
        StartOutcome::Started => client::wait_for_daemon(DAEMON_WAIT)
            .map_err(|error| format!("the daemon did not answer within 10 seconds: {error}")),
        StartOutcome::Cancelled => {
            Err("the in-VPN daemon needs Administrator; the prompt was cancelled".to_owned())
        }
        StartOutcome::Failed(message) => Err(message),
    }
}

/// Ask a daemon this GUI started to shut down.
///
/// Callers disconnect first; this intentionally does nothing when the daemon is
/// already gone, so the final quit path cannot get stuck on a dead pipe.
pub fn shutdown() -> Result<(), String> {
    match client::request(&Request::shutdown(), Some(SHUTDOWN_TIMEOUT)) {
        Ok(response) if response.ok => Ok(()),
        Ok(response) => Err(response
            .error
            .unwrap_or_else(|| "the daemon refused to shut down".to_owned())),
        Err(error) if error.is_unavailable() => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

/// Read the per-user autostart task state without elevation.
pub fn autostart_status() -> Result<TaskState, String> {
    autostart::status().map_err(|error| error.to_string())
}

/// Enable or disable the per-user autostart task through `aevand`.
///
/// The write goes through the existing `--install-autostart` /
/// `--remove-autostart` commands, with one UAC prompt. Success is confirmed by
/// polling the read-only status rather than guessing from the spawn result.
pub fn set_autostart(enabled: bool) -> Result<TaskState, String> {
    let executable = daemon_binary()?;
    let argument = if enabled {
        "--install-autostart"
    } else {
        "--remove-autostart"
    };
    match elevate::start_elevated(&executable, &[argument]) {
        StartOutcome::Started => {}
        StartOutcome::Cancelled => {
            return Err(
                "changing start at login needs Administrator; the prompt was cancelled".to_owned(),
            )
        }
        StartOutcome::Failed(message) => return Err(message),
    }

    let expected = if enabled {
        TaskState::Present
    } else {
        TaskState::Absent
    };
    let start = std::time::Instant::now();
    loop {
        match autostart::status() {
            Ok(state) if state == expected => return Ok(state),
            Ok(_) if start.elapsed() < AUTOSTART_WAIT => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Ok(state) => {
                return Err(format!(
                "aevand did not change the autostart task to {expected:?} (it reports {state:?})"
            ))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn daemon_binary() -> Result<PathBuf, String> {
    client::daemon_binary_beside_executable().ok_or_else(|| {
        let name = if cfg!(windows) {
            "aevand.exe"
        } else {
            "aevand"
        };
        let current = std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "aevan-gui".to_owned());
        format!("{name} is missing beside {current}")
    })
}

fn expect_status(response: Response) -> Result<StatusReport, ClientError> {
    if response.ok {
        Ok(response.status.unwrap_or_default())
    } else {
        // A daemon-reported failure is not a reach failure. Represent it on the
        // "transport" side so the view model shows it as `Failed{reason}`.
        Err(ClientError::Transport(response.error.unwrap_or_else(
            || "the daemon reported an error".to_owned(),
        )))
    }
}
