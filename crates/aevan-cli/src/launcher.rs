//! `aevan` with no subcommand: ensure `aevand`, then open `aevan-gui`.
//!
//! This is the only place that may start the daemon implicitly. The decision
//! logic is a pure function over [`LaunchEnvironment`], so tests never spawn a
//! process, show a UAC prompt or touch the real control endpoint.
//!
//! Fail-soft rules:
//!
//! * a missing `aevand` or a dismissed UAC prompt still opens the GUI, which
//!   shows the daemon-unavailable state and its explicit start action;
//! * a missing `aevan-gui` is reported by name, because there is nothing to open;
//! * no credentials are involved anywhere in this module.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aevan_core::{AevanError, AevanResult};
use aevan_daemon::client;
use aevan_daemon::elevate::{self, StartOutcome};
use aevan_daemon::Request;

/// How the launcher tried to provide `aevand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonStatus {
    /// The control endpoint answered; nothing was started.
    AlreadyRunning,
    /// The elevated start was accepted and the endpoint answered.
    Started,
    /// The elevated start was accepted but the endpoint never answered.
    StartTimedOut,
    /// The user dismissed the single UAC prompt.
    UacCancelled,
    /// The shell or the daemon start failed.
    StartFailed(String),
    /// `aevand` is not beside `aevan`.
    MissingBinary(PathBuf),
}

/// What the launcher did and what the operator should be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSummary {
    /// Daemon provisioning outcome.
    pub daemon: DaemonStatus,
    /// Whether `aevan-gui` was spawned successfully.
    pub gui_launched: bool,
    /// One line per non-fatal notice, in the order they should be printed.
    pub notices: Vec<String>,
    /// A fatal message when the GUI could not be found or started.
    pub failure: Option<String>,
}

#[cfg(test)]
impl LaunchSummary {
    /// The process exit code: success once the GUI was launched.
    pub fn exit_code(&self) -> u8 {
        if self.gui_launched {
            0
        } else {
            1
        }
    }
}

/// The side effects the launcher needs.
///
/// Production uses [`SystemEnvironment`]. Tests use a recording fake, so no
/// process, pipe or UAC prompt is involved.
pub trait LaunchEnvironment {
    /// Whether the control endpoint currently answers.
    fn daemon_reachable(&mut self) -> bool;
    /// The current `aevan` executable, used for accurate missing-file messages.
    fn current_executable(&self) -> PathBuf;
    /// Resolve a sibling executable name beside `aevan`.
    fn sibling(&self, name: &str) -> Option<PathBuf>;
    /// Ask the OS to start the daemon elevated.
    fn start_daemon_elevated(&mut self, executable: &Path) -> StartOutcome;
    /// Wait for the control endpoint to answer.
    fn wait_for_daemon(&mut self, timeout: Duration) -> bool;
    /// Start the GUI detached.
    fn launch_gui(&mut self, executable: &Path) -> Result<(), String>;
}

const DAEMON_NAME: &str = if cfg!(windows) {
    "aevand.exe"
} else {
    "aevand"
};
const GUI_NAME: &str = if cfg!(windows) {
    "aevan-gui.exe"
} else {
    "aevan-gui"
};
const DAEMON_WAIT: Duration = Duration::from_secs(10);

/// Ensure the daemon, then launch the GUI.
pub fn run(environment: &mut dyn LaunchEnvironment) -> LaunchSummary {
    let current = environment.current_executable();
    let current_name = file_name(&current);
    let daemon = environment.sibling(DAEMON_NAME);
    let gui = environment.sibling(GUI_NAME);

    let Some(gui) = gui else {
        return LaunchSummary {
            daemon: DaemonStatus::AlreadyRunning,
            gui_launched: false,
            notices: Vec::new(),
            failure: Some(format!("{GUI_NAME} is missing beside {current_name}")),
        };
    };

    let mut notices = Vec::new();
    let daemon_status = if environment.daemon_reachable() {
        DaemonStatus::AlreadyRunning
    } else {
        match daemon {
            None => {
                let missing = current
                    .parent()
                    .map(|parent| parent.join(DAEMON_NAME))
                    .unwrap_or_else(|| PathBuf::from(DAEMON_NAME));
                notices.push(format!(
                    "{DAEMON_NAME} is missing beside {current_name}; the GUI will show how to start the daemon"
                ));
                DaemonStatus::MissingBinary(missing)
            }
            Some(executable) => match environment.start_daemon_elevated(&executable) {
                StartOutcome::Started => {
                    if environment.wait_for_daemon(DAEMON_WAIT) {
                        DaemonStatus::Started
                    } else {
                        notices.push(
                            "aevand was started with Administrator but did not answer within 10 seconds; the GUI will keep retrying"
                                .to_owned(),
                        );
                        DaemonStatus::StartTimedOut
                    }
                }
                StartOutcome::Cancelled => {
                    notices.push(
                        "the in-VPN daemon needs Administrator; the GUI will show how to start it"
                            .to_owned(),
                    );
                    DaemonStatus::UacCancelled
                }
                StartOutcome::Failed(message) => {
                    notices.push(format!(
                        "{message}; the GUI will show how to start the daemon"
                    ));
                    DaemonStatus::StartFailed(message)
                }
            },
        }
    };

    match environment.launch_gui(&gui) {
        Ok(()) => LaunchSummary {
            daemon: daemon_status,
            gui_launched: true,
            notices,
            failure: None,
        },
        Err(message) => LaunchSummary {
            daemon: daemon_status,
            gui_launched: false,
            notices,
            failure: Some(format!("could not start {GUI_NAME}: {message}")),
        },
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Drive the real daemon, UAC prompt and GUI process.
pub struct SystemEnvironment;

impl LaunchEnvironment for SystemEnvironment {
    fn daemon_reachable(&mut self) -> bool {
        match client::request(&Request::status(), Some(Duration::from_secs(2))) {
            Ok(_) => true,
            // Access-denied or a protocol mismatch means the endpoint exists;
            // the GUI should report that rather than start a second daemon.
            Err(error) => !error.is_unavailable(),
        }
    }

    fn current_executable(&self) -> PathBuf {
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aevan"))
    }

    fn sibling(&self, name: &str) -> Option<PathBuf> {
        let executable = self.current_executable();
        let candidate = executable.parent()?.join(name);
        candidate.is_file().then_some(candidate)
    }

    fn start_daemon_elevated(&mut self, executable: &Path) -> StartOutcome {
        elevate::start_elevated(executable, &[])
    }

    fn wait_for_daemon(&mut self, timeout: Duration) -> bool {
        client::wait_for_daemon(timeout).is_ok()
    }

    fn launch_gui(&mut self, executable: &Path) -> Result<(), String> {
        elevate::spawn_detached(executable).map_err(|error| error.to_string())
    }
}

/// Run the launcher and translate its summary into CLI output.
pub fn launch() -> AevanResult<()> {
    let summary = run(&mut SystemEnvironment);
    for notice in &summary.notices {
        println!("{notice}");
    }
    match summary.failure {
        Some(message) => Err(AevanError::Config(message)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use aevan_daemon::elevate::StartOutcome;

    use super::{run, DaemonStatus, LaunchEnvironment, DAEMON_NAME, GUI_NAME};

    // Tests must run on every platform the CLI builds for, so the install root
    // and the binary names come from the same constants the launcher uses
    // instead of a hard-coded Windows path.
    #[cfg(windows)]
    const ROOT: &str = r"C:\Program Files\aevan";
    #[cfg(not(windows))]
    const ROOT: &str = "/opt/aevan";
    #[cfg(windows)]
    const AEVAN_NAME: &str = "aevan.exe";
    #[cfg(not(windows))]
    const AEVAN_NAME: &str = "aevan";

    fn aevan_path() -> std::path::PathBuf {
        std::path::Path::new(ROOT).join(AEVAN_NAME)
    }
    fn aevand_path() -> std::path::PathBuf {
        std::path::Path::new(ROOT).join(DAEMON_NAME)
    }
    fn gui_path() -> std::path::PathBuf {
        std::path::Path::new(ROOT).join(GUI_NAME)
    }

    #[derive(Default)]
    struct Fake {
        reachable: bool,
        daemon_present: bool,
        gui_present: bool,
        start: Option<StartOutcome>,
        answers: bool,
        gui_error: Option<String>,
        started: Vec<PathBuf>,
        launched: Vec<PathBuf>,
        waits: Vec<Duration>,
    }

    impl Fake {
        fn ready() -> Self {
            Self {
                reachable: true,
                daemon_present: true,
                gui_present: true,
                answers: true,
                ..Self::default()
            }
        }

        fn without_daemon() -> Self {
            Self {
                reachable: false,
                start: Some(StartOutcome::Started),
                ..Self::ready()
            }
        }
    }

    impl LaunchEnvironment for Fake {
        fn daemon_reachable(&mut self) -> bool {
            self.reachable
        }

        fn current_executable(&self) -> PathBuf {
            aevan_path()
        }

        fn sibling(&self, name: &str) -> Option<PathBuf> {
            match name {
                DAEMON_NAME if self.daemon_present => Some(aevand_path()),
                GUI_NAME if self.gui_present => Some(gui_path()),
                _ => None,
            }
        }

        fn start_daemon_elevated(&mut self, executable: &Path) -> StartOutcome {
            self.started.push(executable.to_path_buf());
            self.start
                .clone()
                .unwrap_or(StartOutcome::Failed("not configured".into()))
        }

        fn wait_for_daemon(&mut self, timeout: Duration) -> bool {
            self.waits.push(timeout);
            self.answers
        }

        fn launch_gui(&mut self, executable: &Path) -> Result<(), String> {
            self.launched.push(executable.to_path_buf());
            match &self.gui_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn a_running_daemon_is_not_started_again() {
        let mut fake = Fake::ready();
        let summary = run(&mut fake);

        assert_eq!(summary.daemon, DaemonStatus::AlreadyRunning);
        assert!(summary.gui_launched);
        assert_eq!(summary.exit_code(), 0);
        assert!(fake.started.is_empty(), "must not start a second daemon");
        assert!(fake.waits.is_empty());
        assert_eq!(fake.launched, vec![gui_path()]);
    }

    #[test]
    fn a_missing_daemon_is_started_once_and_waited_for() {
        let mut fake = Fake::without_daemon();
        let summary = run(&mut fake);

        assert_eq!(summary.daemon, DaemonStatus::Started);
        assert!(summary.gui_launched);
        assert_eq!(fake.started, vec![aevand_path()]);
        assert_eq!(fake.waits, vec![Duration::from_secs(10)]);
        assert_eq!(fake.launched, vec![gui_path()]);
    }

    #[test]
    fn a_cancelled_uac_prompt_still_opens_the_gui_with_one_sentence() {
        let mut fake = Fake::without_daemon();
        fake.start = Some(StartOutcome::Cancelled);
        let summary = run(&mut fake);

        assert_eq!(summary.daemon, DaemonStatus::UacCancelled);
        assert!(summary.gui_launched);
        assert_eq!(summary.notices.len(), 1);
        assert_eq!(
            summary.notices[0],
            "the in-VPN daemon needs Administrator; the GUI will show how to start it"
        );
        assert!(fake.waits.is_empty());
        assert_eq!(fake.launched, vec![gui_path()]);
    }

    #[test]
    fn a_missing_daemon_binary_is_named_and_the_gui_still_opens() {
        let mut fake = Fake::without_daemon();
        fake.daemon_present = false;
        let summary = run(&mut fake);

        assert_eq!(summary.daemon, DaemonStatus::MissingBinary(aevand_path()));
        assert!(summary.gui_launched);
        assert!(fake.started.is_empty());
        assert!(
            summary.notices[0].contains(&format!("{DAEMON_NAME} is missing beside {AEVAN_NAME}"))
        );
    }

    #[test]
    fn a_missing_gui_binary_is_named_and_nothing_is_started() {
        let mut fake = Fake::without_daemon();
        fake.gui_present = false;
        let summary = run(&mut fake);

        assert!(!summary.gui_launched);
        assert_eq!(summary.exit_code(), 1);
        assert!(
            fake.started.is_empty(),
            "do not start the daemon for nothing"
        );
        assert_eq!(
            summary.failure.as_deref(),
            Some(format!("{GUI_NAME} is missing beside {AEVAN_NAME}").as_str())
        );
    }

    #[test]
    fn a_start_that_never_answers_still_opens_the_gui() {
        let mut fake = Fake::without_daemon();
        fake.answers = false;
        let summary = run(&mut fake);

        assert_eq!(summary.daemon, DaemonStatus::StartTimedOut);
        assert!(summary.gui_launched);
        assert!(summary.notices[0].contains("did not answer within 10 seconds"));
    }

    #[test]
    fn a_failed_elevated_start_still_opens_the_gui_and_reports_the_reason() {
        let mut fake = Fake::without_daemon();
        fake.start = Some(StartOutcome::Failed("shell refused".into()));
        let summary = run(&mut fake);

        assert_eq!(
            summary.daemon,
            DaemonStatus::StartFailed("shell refused".into())
        );
        assert!(summary.gui_launched);
        assert!(summary.notices[0].contains("shell refused"));
    }

    #[test]
    fn a_gui_spawn_failure_is_fatal() {
        let mut fake = Fake::ready();
        fake.gui_error = Some("denied".into());
        let summary = run(&mut fake);

        assert!(!summary.gui_launched);
        assert_eq!(summary.exit_code(), 1);
        assert_eq!(
            summary.failure.as_deref(),
            Some(format!("could not start {GUI_NAME}: denied").as_str())
        );
    }
}
