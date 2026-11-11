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
#[cfg(not(target_os = "macos"))]
use aevan_daemon::elevate::{self, StartOutcome};
use aevan_daemon::{Request, Response, StatusReport};

#[cfg(target_os = "macos")]
pub use crate::relaunch::ServiceState;

use crate::view_model::{totp_account, ConnectCredentials, TotpEnrolment, KEYRING_SERVICE};

const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const DAEMON_WAIT: Duration = Duration::from_secs(10);
#[cfg(windows)]
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

/// One successful connect plus the realm detected on first use, if any.
#[derive(Debug, Clone)]
pub struct ConnectOutcome {
    /// Daemon status after the connect.
    pub status: StatusReport,
    /// Realm written back into the store when it was auto-detected.
    pub detected_realm: Option<String>,
}

/// Submit exactly one `connect` request.
///
/// An empty profile realm is detected from the gateway first and persisted, so
/// the request carries the value the vendor client would have used. Detection
/// is one credential-free `GET` and costs no login attempt.
///
/// There is no read timeout, matching the CLI: the daemon returns when the
/// single authentication attempt and the apply step have finished.
pub fn connect(credentials: ConnectCredentials) -> Result<ConnectOutcome, ClientError> {
    let (profile, detected_realm) = local_profile_with_realm(credentials.profile_name())?;
    let request = credentials.into_request(&profile.url, &profile.realm);
    let response = client::request(&request, None)?;
    Ok(ConnectOutcome {
        status: expect_status(response)?,
        detected_realm,
    })
}

/// Resolve a profile from this user's store before talking to the daemon.
///
/// The daemon may run as root with a different (empty) store, so sending a
/// name alone would fail there. An empty realm is detected and saved here,
/// where the owner's store lives.
fn local_profile_with_realm(name: &str) -> Result<(Profile, Option<String>), ClientError> {
    let path = ProfileStore::default_path().map_err(|error| {
        ClientError::Transport(format!("cannot resolve the local profile store: {error}"))
    })?;
    let mut store = ProfileStore::load(&path).map_err(|error| {
        ClientError::Transport(format!(
            "cannot read the local profile store {}: {error}",
            path.display()
        ))
    })?;
    let profile = store.get(name).cloned().ok_or_else(|| {
        ClientError::Transport(format!(
            "profile '{name}' was not found in {}; add it before connecting",
            path.display()
        ))
    })?;
    if profile.has_realm() {
        return Ok((profile, None));
    }

    let url = aevan_proto::Url::parse(&profile.url)
        .map_err(|error| ClientError::Transport(format!("invalid gateway URL: {error}")))?;
    let realm = aevan_proto::detect_realm(&url)
        .map_err(|error| ClientError::Transport(error.to_string()))?;

    let mut detected = profile;
    detected.realm = realm.clone();
    detected
        .validate()
        .map_err(|error| ClientError::Transport(error.to_string()))?;
    store
        .upsert(detected.clone())
        .map_err(|error| ClientError::Transport(error.to_string()))?;
    store
        .save(&path)
        .map_err(|error| ClientError::Transport(error.to_string()))?;
    Ok((detected, Some(realm)))
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

/// Read and decode the TOTP secret for a profile from the owner's secret store.
///
/// `Ok(None)` means "no TOTP enrolled". A backend or decode failure is returned
/// so the Settings sheet can show it instead of silently treating it as "not
/// enrolled". Reading never spawns a process, opens a URL or asks for
/// elevation. This function never logs or returns the encoded secret.
pub fn totp_secret(profile: &str) -> Result<Option<Vec<u8>>, String> {
    use aevan_secrets::decode_base32;

    let store = open_totp_store()?;
    let account = totp_account(profile);
    match store.get(KEYRING_SERVICE, &account) {
        Ok(Some(secret)) => decode_base32(secret.expose())
            .map(Some)
            .map_err(|_| "the stored TOTP secret is not valid base32".to_owned()),
        Ok(None) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

/// Write a validated TOTP secret and verify that it round-trips.
///
/// The stored document is read back immediately and a code is generated from
/// the stored bytes; it must equal the code generated from the enrolled bytes.
/// Every failure is returned as text so the Settings sheet can display it. The
/// secret itself is never part of an error message.
pub fn save_totp_secret(enrolment: TotpEnrolment) -> Result<(String, Vec<u8>), String> {
    let mut store = open_totp_store()?;
    save_totp_secret_into(store.as_mut(), enrolment, crate::view_model::now_unix())
}

fn save_totp_secret_into(
    store: &mut dyn aevan_secrets::SecretStore,
    enrolment: TotpEnrolment,
    now: u64,
) -> Result<(String, Vec<u8>), String> {
    use aevan_secrets::{decode_base32, Secret, Totp};

    let profile = enrolment.profile().to_owned();
    let encoded = enrolment.encoded().to_owned();
    let decoded = enrolment.into_decoded();
    let expected_code = Totp::default()
        .code_at(&decoded, now)
        .map_err(|_| "the secret is not valid base32".to_owned())?;

    let account = totp_account(&profile);
    store
        .set(KEYRING_SERVICE, &account, Secret::new(encoded))
        .map_err(|error| error.to_string())?;

    let stored = store
        .get(KEYRING_SERVICE, &account)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the secret was not stored; the store returned no entry".to_owned())?;
    let decoded = decode_base32(stored.expose())
        .map_err(|_| "the stored secret is not valid base32".to_owned())?;
    let stored_code = Totp::default()
        .code_at(&decoded, now)
        .map_err(|_| "the stored secret is not valid base32".to_owned())?;
    if stored_code != expected_code {
        return Err(
            "the stored secret did not round-trip; the saved code does not match".to_owned(),
        );
    }
    Ok((profile, decoded))
}

/// Remove a profile's TOTP secret from the owner's secret store.
pub fn remove_totp_secret(profile: &str) -> Result<(), String> {
    let mut store = open_totp_store()?;
    store
        .delete(KEYRING_SERVICE, &totp_account(profile))
        .map_err(|error| error.to_string())
}

/// Select the per-user TOTP backend.
///
/// Windows uses Credential Manager. macOS and Linux use the owner-only file
/// backend because this build does not compile a native keyring backend there;
/// the file's directory is 0700 and the file is 0600 on Unix.
#[cfg(windows)]
fn open_totp_store() -> Result<Box<dyn aevan_secrets::SecretStore>, String> {
    Ok(Box::new(aevan_secrets::KeyringStore::new()))
}

#[cfg(not(windows))]
fn open_totp_store() -> Result<Box<dyn aevan_secrets::SecretStore>, String> {
    let path = aevan_core::paths::default_secrets_path().map_err(|error| error.to_string())?;
    Ok(Box::new(aevan_secrets::FileStore::new(path)))
}

/// Start `aevand` beside this GUI, then wait for the control endpoint.
///
/// macOS registers the bundled LaunchDaemon with ServiceManagement once and
/// reuses it afterwards; an ad-hoc signed build falls back to the legacy
/// LaunchDaemon with one administrator prompt. Windows keeps the single UAC
/// elevation. Nothing is started silently: this is only called by the explicit
/// start action.
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

    use crate::macos_bundle;
    use crate::macos_elevate;
    use crate::macos_service;
    use crate::relaunch::{self, RegisterMethod, RelaunchOps, StartMethod};
    use crate::start_log;

    // Resolve the bundle the way macOS does and check every expected artifact
    // before any registration. A translocated or incomplete bundle must never
    // reach ServiceManagement, and the failure carries the exact paths checked.
    let bundle = match macos_bundle::verify_resolved() {
        Ok(bundle) => bundle,
        Err(problem) => {
            let message = problem.to_string();
            let _ = start_log::record_default(
                &format!(
                    "macOS daemon registration bundle check ({})",
                    macos_bundle::PLIST_RELATIVE_PATH
                ),
                None,
                &message,
            );
            tracing::warn!(
                reason = %message,
                bundle = problem.bundle_root().map(|root| root.display().to_string()),
                "the app bundle cannot register the daemon"
            );
            return Err(message);
        }
    };
    tracing::debug!(
        bundle = %bundle.root.display(),
        plist = %bundle.plist.display(),
        "verified the bundled daemon plist"
    );

    struct MacOps<'a> {
        executable: &'a Path,
    }

    impl RelaunchOps for MacOps<'_> {
        fn socket_answers(&self) -> bool {
            client::request(&Request::status(), Some(STATUS_TIMEOUT)).is_ok()
        }

        fn service_status(&self) -> Result<ServiceState, String> {
            macos_service::status()
        }

        fn register(&self) -> Result<RegisterMethod, String> {
            match macos_service::register() {
                Ok(()) => Ok(RegisterMethod::ServiceManagement),
                Err(error) if macos_elevate::should_fall_back(&error) => {
                    // An ad-hoc signed build cannot use SMAppService. If the
                    // legacy plist already exists, macOS started it at boot and
                    // later launches must not prompt again.
                    if !macos_elevate::daemon_installed() {
                        macos_elevate::install(self.executable)?;
                    }
                    Ok(RegisterMethod::LegacyLaunchDaemon)
                }
                Err(error) => Err(error),
            }
        }

        fn kickstart(&self) -> Result<(), String> {
            launchd::kickstart()
        }

        fn wait_ready(&self) -> Result<(), String> {
            client::wait_for_daemon(DAEMON_WAIT)
                .map_err(|error| format!("the daemon did not answer within 10 seconds: {error}"))
        }
    }

    match relaunch::relaunch(&MacOps { executable }) {
        Ok(report) => {
            let command = match report.method {
                StartMethod::LegacyInstalled => {
                    format!(
                        "legacy LaunchDaemon install ({})",
                        macos_elevate::INSTALLED_PLIST
                    )
                }
                _ => format!("SMAppService daemon registration ({:?})", report.method),
            };
            let _ = start_log::record_default(&command, None, "");
            tracing::info!(method = ?report.method, "daemon service start finished");
            Ok(())
        }
        Err(error) => {
            let _ = start_log::record_default(
                &format!(
                    "macOS daemon registration (SMAppService, then legacy fallback, {})",
                    macos_service::PLIST_NAME
                ),
                None,
                &error,
            );
            Err(error)
        }
    }
}

#[cfg(target_os = "macos")]
pub fn daemon_service_status() -> Result<ServiceState, String> {
    crate::macos_service::status()
}

#[cfg(target_os = "macos")]
pub fn unregister_daemon_service() -> Result<(), String> {
    crate::macos_service::unregister()
}

#[cfg(target_os = "macos")]
pub fn open_login_items() {
    crate::macos_service::open_login_items();
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

/// Enable or disable the per-user start-at-login item.
///
/// Windows writes the existing elevated `aevand` logon task. macOS writes the
/// user's LaunchAgent and Linux writes the XDG autostart entry; neither needs
/// elevation and neither spawns a helper. Success is confirmed by reading the
/// real state back rather than guessing from the write result.
pub fn set_autostart(enabled: bool) -> Result<TaskState, String> {
    let expected = if enabled {
        TaskState::Present
    } else {
        TaskState::Absent
    };

    #[cfg(windows)]
    {
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
                    "changing start at login needs Administrator; the prompt was cancelled"
                        .to_owned(),
                )
            }
            StartOutcome::Failed(message) => return Err(message),
        }

        let start = std::time::Instant::now();
        loop {
            match autostart::status() {
                Ok(state) if state == expected => return Ok(state),
                Ok(_) if start.elapsed() < AUTOSTART_WAIT => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Ok(state) => {
                    return Err(format!(
                        "The Aevan daemon did not change the autostart task to {expected:?} (it reports {state:?})"
                    ))
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    }

    #[cfg(not(windows))]
    {
        let result = if enabled {
            autostart::install(None).map(|_| ())
        } else {
            autostart::remove()
        };
        result.map_err(|error| error.to_string())?;
        let state = autostart::status().map_err(|error| error.to_string())?;
        if state == expected {
            Ok(state)
        } else {
            Err(format!(
                "the login item did not change to {expected:?} (it reports {state:?})"
            ))
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
        format!("The Aevan daemon program ({name}) is missing beside {current}; reinstall Aevan")
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use aevan_core::Profile;
    use aevan_secrets::{decode_base32, FileStore, SecretStore, Totp};

    use super::*;
    use crate::view_model::ViewModel;

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
                "aevan-gui-secret-{label}-{}-{nanos}-{unique}",
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

    fn enrolment() -> TotpEnrolment {
        let mut store = ProfileStore::default();
        let profile =
            Profile::new("example", "https://vpn.example.net/realm", "realm").expect("profile");
        store.add(profile).expect("add profile");
        let mut vm = ViewModel::new(&store, "endpoint".into(), 0);
        vm.select_for_settings("example", 0);
        vm.set_totp_input("JBSWY3DPEHPK3PXP".into());
        vm.validate_totp_input().expect("valid secret");
        vm.take_totp_enrolment().expect("enrolment")
    }

    #[test]
    fn saving_totp_round_trips_and_the_stored_secret_generates_a_code() {
        let temp = TempDir::new("round-trip");
        let path = temp.path().join("aevan").join("secrets.json");
        let mut store = FileStore::new(&path);

        let (profile, decoded) =
            save_totp_secret_into(&mut store, enrolment(), 1_234).expect("save and verify");
        assert_eq!(profile, "example");

        let reloaded = FileStore::new(&path)
            .get(KEYRING_SERVICE, &totp_account("example"))
            .expect("reload")
            .expect("stored");
        let reloaded = decode_base32(reloaded.expose()).expect("decode stored secret");
        assert_eq!(reloaded, decoded);

        let expected = decode_base32("JBSWY3DPEHPK3PXP").expect("decode fixture");
        assert_eq!(
            Totp::default()
                .code_at(&reloaded, 1_234)
                .expect("stored code"),
            Totp::default()
                .code_at(&expected, 1_234)
                .expect("fixture code")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_is_reported_without_the_secret() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new("read-only");
        let directory = temp.path().join("read-only");
        std::fs::create_dir_all(&directory).expect("create directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
            .expect("make read-only");

        let mut store = FileStore::new(directory.join("secrets.json"));
        let result = save_totp_secret_into(&mut store, enrolment(), 0);

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("restore permissions");
        let error = result.expect_err("a read-only directory cannot store the secret");
        assert!(error.contains("secrets.json"), "{error}");
        assert!(!error.contains("JBSWY3DPEHPK3PXP"), "{error}");
    }

    #[test]
    fn saving_the_same_profile_twice_replaces_the_secret() {
        let temp = TempDir::new("replace");
        let path = temp.path().join("secrets.json");
        let mut store = FileStore::new(&path);
        save_totp_secret_into(&mut store, enrolment(), 0).expect("first save");

        let mut store = FileStore::new(&path);
        let (_, decoded) =
            save_totp_secret_into(&mut store, replacement_enrolment("GEZDGNBVGY3TQOJQ"), 0)
                .expect("second save");
        let reloaded = FileStore::new(&path)
            .get(KEYRING_SERVICE, &totp_account("example"))
            .expect("reload")
            .expect("stored");
        assert_eq!(
            decode_base32(reloaded.expose()).expect("decode"),
            decoded,
            "the second save replaces the first cleanly"
        );
    }

    fn replacement_enrolment(secret: &str) -> TotpEnrolment {
        let mut store = ProfileStore::default();
        let profile =
            Profile::new("example", "https://vpn.example.net/realm", "realm").expect("profile");
        store.add(profile).expect("add profile");
        let mut vm = ViewModel::new(&store, "endpoint".into(), 0);
        vm.select_for_settings("example", 0);
        vm.set_totp_input(secret.into());
        vm.validate_totp_input().expect("valid secret");
        vm.take_totp_enrolment().expect("enrolment")
    }
}
