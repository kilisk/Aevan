#![deny(unsafe_code)]
//! `aevand` — the aevan daemon.
//!
//! Runs in the foreground, owns the control endpoint and the one live tunnel,
//! and recovers an interrupted configuration journal before accepting requests.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;

use aevan_core::{AevanError, AevanResult};
use aevan_daemon::autostart::{self, TaskState};
use aevan_daemon::{build_runtime, journal, server, Daemon, LogHub, LogLayer, RecoveryReport};

const HELP: &str = "\
aevand — the aevan daemon

Usage:
  aevand                 Run the daemon in the foreground (default)
  aevand --recover       Run crash-journal recovery once and exit
  aevand --install-autostart [--user <sid|DOMAIN\\name>]
                        Register the per-user 'Aevan' logon task (Administrator)
  aevand --remove-autostart
                        Delete the per-user 'Aevan' logon task (Administrator)
  aevand --autostart-status
                        Report whether the 'Aevan' logon task exists
  aevand -h, --help      Print this help and exit
  aevand -V, --version   Print the version and exit

The autostart task starts aevand at your logon with HighestAvailable. It is
per-user on purpose: profiles and the crash journal live in your %APPDATA%,
so a LocalSystem service would read the wrong store and own the wrong tunnel.
Creating or removing the task requires Administrator and exits 6 otherwise.
--autostart-status exits 0 when present, 1 when absent and 2 when unknown.

Recovery probes the device first, so an absent device clears the journal
without elevation. Live state requires Administrator. --recover prints
rolled_back, skipped_absent and failed, deletes the journal only when nothing
remains, and exits 0 (clean), 6 (needs elevation) or 1 (genuine failure).
";

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Daemon,
    Recover,
    InstallAutostart { user: Option<String> },
    RemoveAutostart,
    AutostartStatus,
    Help,
    Version,
    Unknown(String),
}

fn parse_args<I, S>(args: I) -> Invocation
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Invocation::Daemon;
    };
    let rest: Vec<String> = args.map(|argument| argument.as_ref().to_owned()).collect();
    match first.as_ref() {
        "-h" | "--help" if rest.is_empty() => Invocation::Help,
        "-V" | "--version" if rest.is_empty() => Invocation::Version,
        "--recover" if rest.is_empty() => Invocation::Recover,
        "--install-autostart" => match rest.as_slice() {
            [] => Invocation::InstallAutostart { user: None },
            [flag, user] if flag == "--user" => Invocation::InstallAutostart {
                user: Some(user.clone()),
            },
            [unexpected, ..] => Invocation::Unknown(unexpected.clone()),
        },
        "--remove-autostart" if rest.is_empty() => Invocation::RemoveAutostart,
        "--autostart-status" if rest.is_empty() => Invocation::AutostartStatus,
        "-h" | "--help" | "-V" | "--version" | "--recover" | "--remove-autostart"
        | "--autostart-status" => Invocation::Unknown(rest[0].clone()),
        other => Invocation::Unknown(other.to_owned()),
    }
}

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)) {
        Invocation::Help => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Invocation::Version => {
            println!("aevand {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Invocation::Unknown(argument) => {
            eprintln!("aevand: unrecognized argument '{argument}'");
            eprintln!();
            eprint!("{HELP}");
            ExitCode::from(2)
        }
        Invocation::Recover => ExitCode::from(run_recover()),
        Invocation::InstallAutostart { user } => {
            ExitCode::from(match autostart::install(user.as_deref()) {
                Ok(principal) => {
                    println!("installed the per-user 'Aevan' logon task for {principal}");
                    0
                }
                Err(error) => {
                    eprintln!("aevand: {error}");
                    error.exit_code() as u8
                }
            })
        }
        Invocation::RemoveAutostart => ExitCode::from(match autostart::remove() {
            Ok(()) => {
                println!("the per-user 'Aevan' logon task is removed (or was already absent)");
                0
            }
            Err(error) => {
                eprintln!("aevand: {error}");
                error.exit_code() as u8
            }
        }),
        Invocation::AutostartStatus => ExitCode::from(run_autostart_status()),
        Invocation::Daemon => run_daemon(),
    }
}

fn run_autostart_status() -> u8 {
    match autostart::status() {
        Ok(TaskState::Present) => {
            println!("present");
            0
        }
        Ok(TaskState::Absent) => {
            println!("absent");
            1
        }
        Ok(TaskState::Unknown) => {
            eprintln!(
                "aevand: the state of the '{}' task could not be determined",
                autostart::TASK_NAME
            );
            2
        }
        Err(error) => {
            eprintln!("aevand: {error}");
            error.exit_code() as u8
        }
    }
}

fn run_daemon() -> ExitCode {
    let logs = LogHub::new();
    init_tracing(logs.clone());

    match run(logs) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "aevand stopped with an error");
            eprintln!("{}", fatal_line(&error));
            ExitCode::from(error.exit_code() as u8)
        }
    }
}

/// Resolve the daemon's state directory.
///
/// launchd starts system daemons with **no `HOME`**, so `config_dir()` fails there even though the
/// process is root and perfectly able to write its own state. Fall back to root's real home in that
/// case instead of exiting 1 before the socket is ever opened.
fn state_dir() -> AevanResult<PathBuf> {
    let error = match aevan_core::paths::config_dir() {
        Ok(dir) => return Ok(dir),
        Err(error) => error,
    };
    // Root, but no HOME to resolve: launchd does exactly this.
    #[cfg(target_os = "macos")]
    if server::process_is_root() {
        return Ok(PathBuf::from("/var/root/Library/Application Support/aevan"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    if server::process_is_root() {
        return Ok(PathBuf::from("/root/.config/aevan"));
    }
    Err(error)
}

fn run_recover() -> u8 {
    let config_dir = match state_dir() {
        Ok(dir) => dir,
        Err(error) => {
            eprintln!("aevand: {error}");
            return 1;
        }
    };
    let path = journal::journal_path(&config_dir);
    recover_at(&path, journal::recover)
}

fn recover_at<F>(path: &Path, recover: F) -> u8
where
    F: FnOnce(&Path) -> AevanResult<Option<RecoveryReport>>,
{
    match recover(path) {
        Ok(report) => {
            print_recovery(report.as_ref(), path);
            match report {
                Some(report) if report.failed() > 0 => 1,
                _ => 0,
            }
        }
        Err(error) => {
            eprintln!("aevand: {error}");
            match error {
                AevanError::Privilege(_) => 6,
                _ => 1,
            }
        }
    }
}

fn print_recovery(report: Option<&RecoveryReport>, path: &Path) {
    let Some(report) = report else {
        println!("rolled_back: 0");
        println!("skipped_absent: 0");
        println!("failed: 0");
        println!("no journal is present");
        return;
    };

    let journal = report
        .journal
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| path.display().to_string());
    println!("journal: {journal}");
    println!("rolled_back: {}", report.rolled_back);
    println!("skipped_absent: {}", report.skipped_absent);
    println!("failed: {}", report.failed());
    for failure in &report.failures {
        println!("  {}: {}", failure.step, failure.reason);
    }
    if report.failed() == 0 {
        if report.removed {
            println!("journal recovery complete; nothing left to undo");
        } else {
            println!("no journal is present");
        }
    } else {
        println!("journal recovery is incomplete; the journal is retained at {journal}");
    }
}

fn fatal_line(error: &AevanError) -> String {
    match error {
        // The daemon's start-up failures are already operator-facing sentences;
        // prefixing them would bury the instruction to stop the other daemon.
        AevanError::AlreadyInState(message) => message.clone(),
        _ => format!("aevand: {error}"),
    }
}

fn run(logs: LogHub) -> AevanResult<()> {
    let config_dir = state_dir()?;
    std::fs::create_dir_all(&config_dir)?;
    set_private_directory(&config_dir)?;

    let daemon = Arc::new(Daemon::new(&config_dir, logs));
    let path = journal::journal_path(&config_dir);

    match journal::recover(&path) {
        Ok(Some(report)) => {
            if report.is_complete() {
                tracing::info!(
                    rolled_back = report.rolled_back,
                    skipped_absent = report.skipped_absent,
                    "journal recovery complete; nothing left to undo"
                );
            } else {
                tracing::error!(
                    rolled_back = report.rolled_back,
                    skipped_absent = report.skipped_absent,
                    failures = report.failed(),
                    "journal recovery was incomplete; the journal is retained"
                );
                for failure in &report.failures {
                    tracing::error!(
                        step = %failure.step,
                        failure = %failure.reason,
                        "journal rollback step failed"
                    );
                }
                daemon.mark_recovery_incomplete(report);
            }
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(path = %path.display(), %error, "journal recovery failed");
            daemon.mark_recovery_failed(format!("journal recovery failed: {error}"));
        }
    }

    let runtime = build_runtime().map_err(AevanError::Io)?;
    tracing::info!(milestone = aevan_daemon::MILESTONE, "aevand starting");
    runtime.block_on(server::serve(daemon))
}

fn init_tracing(logs: LogHub) {
    let _ = tracing_subscriber::registry()
        .with(LogLayer::new(logs))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(LevelFilter::INFO),
        )
        .try_init();
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> AevanResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> AevanResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use aevan_tun::{Change, Elevation, RollbackBackend, TunError, UndoOutcome};

    #[test]
    fn already_listening_prints_the_required_line_and_uses_exit_5() {
        let pipe = r"\\.\pipe\aevan";
        let error = server::already_listening(pipe);

        assert_eq!(
            fatal_line(&error),
            r"another aevand is already listening on \\.\pipe\aevan; stop it first"
        );
        assert_eq!(error.exit_code(), 5);
    }

    #[test]
    fn argument_parsing_covers_every_flag() {
        assert_eq!(parse_args(std::iter::empty::<&str>()), Invocation::Daemon);
        assert_eq!(parse_args(["-h"]), Invocation::Help);
        assert_eq!(parse_args(["--help"]), Invocation::Help);
        assert_eq!(parse_args(["-V"]), Invocation::Version);
        assert_eq!(parse_args(["--version"]), Invocation::Version);
        assert_eq!(parse_args(["--recover"]), Invocation::Recover);
        assert_eq!(
            parse_args(["--install-autostart"]),
            Invocation::InstallAutostart { user: None }
        );
        assert_eq!(
            parse_args(["--install-autostart", "--user", "S-1-5-21-1"]),
            Invocation::InstallAutostart {
                user: Some("S-1-5-21-1".into())
            }
        );
        assert_eq!(
            parse_args(["--remove-autostart"]),
            Invocation::RemoveAutostart
        );
        assert_eq!(
            parse_args(["--autostart-status"]),
            Invocation::AutostartStatus
        );
        assert_eq!(
            parse_args(["--bogus"]),
            Invocation::Unknown("--bogus".into())
        );
        assert_eq!(parse_args(["-x"]), Invocation::Unknown("-x".into()));
        assert_eq!(
            parse_args(["--recover", "extra"]),
            Invocation::Unknown("extra".into())
        );
        assert_eq!(
            parse_args(["--install-autostart", "--bogus"]),
            Invocation::Unknown("--bogus".into())
        );
        assert_eq!(
            parse_args(["--remove-autostart", "extra"]),
            Invocation::Unknown("extra".into())
        );
    }

    #[test]
    fn help_and_version_cover_the_documented_surface() {
        assert!(HELP.contains("--recover"));
        assert!(HELP.contains("--install-autostart"));
        assert!(HELP.contains("--remove-autostart"));
        assert!(HELP.contains("--autostart-status"));
        assert!(HELP.contains("-h, --help"));
        assert!(HELP.contains("-V, --version"));
        assert!(HELP.contains("rolled_back"));
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }

    #[derive(Default)]
    struct CleanBackend;

    impl RollbackBackend for CleanBackend {
        fn apply(&mut self, _change: &Change) -> Result<(), TunError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct AbsentBackend;

    impl RollbackBackend for AbsentBackend {
        fn apply(&mut self, _change: &Change) -> Result<(), TunError> {
            Ok(())
        }

        fn device_present(&mut self) -> Result<bool, TunError> {
            Ok(false)
        }
    }

    struct DirtyBackend;

    impl RollbackBackend for DirtyBackend {
        fn apply(&mut self, _change: &Change) -> Result<(), TunError> {
            Ok(())
        }

        fn device_present(&mut self) -> Result<bool, TunError> {
            Ok(true)
        }

        fn undo(&mut self, _change: &Change) -> Result<UndoOutcome, TunError> {
            Err(TunError::Permission("denied to change routes".into()))
        }
    }

    fn run_recovery<B: RollbackBackend>(path: &Path, backend: &mut B, elevation: Elevation) -> u8 {
        recover_at(path, |path| {
            Ok(Some(journal::recover_with_elevation(
                path, backend, elevation,
            )?))
        })
    }

    fn change() -> Change {
        Change::SetMtu {
            old: None,
            new: Some(1396),
        }
    }

    fn journal_with(change: Option<Change>) -> (TempDir, PathBuf) {
        let dir = TempDir::new("recover");
        let path = journal::journal_path(&dir.0);
        let mut journal = aevan_daemon::Journal::create(path.clone(), "aevan").expect("create");
        if let Some(change) = change {
            journal.record(&change).expect("record");
        }
        drop(journal);
        (dir, path)
    }

    #[test]
    fn recover_command_is_clean_for_an_empty_journal() {
        let (_dir, path) = journal_with(None);
        let mut backend = CleanBackend;
        assert_eq!(run_recovery(&path, &mut backend, Elevation::NotElevated), 0);
        assert!(!path.exists());
    }

    #[test]
    fn recover_command_clears_an_absent_only_journal_without_elevation() {
        let (_dir, path) = journal_with(Some(change()));
        let mut backend = AbsentBackend;
        assert_eq!(run_recovery(&path, &mut backend, Elevation::NotElevated), 0);
        assert!(!path.exists());
    }

    #[test]
    fn recover_command_keeps_a_genuinely_dirty_journal_and_exits_1() {
        let (_dir, path) = journal_with(Some(change()));
        let mut backend = DirtyBackend;
        assert_eq!(run_recovery(&path, &mut backend, Elevation::Elevated), 1);
        assert!(path.exists());
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    #[test]
    fn recover_command_needs_elevation_for_live_state() {
        let (_dir, path) = journal_with(Some(change()));
        let mut backend = CleanBackend;
        assert_eq!(run_recovery(&path, &mut backend, Elevation::NotElevated), 6);
        assert!(path.exists());
    }

    #[test]
    fn recover_command_treats_a_malformed_journal_as_a_genuine_failure() {
        let dir = TempDir::new("recover-malformed");
        let path = journal::journal_path(&dir.0);
        fs::write(&path, b"not json").expect("write malformed journal");
        assert_eq!(recover_at(&path, journal::recover), 1);
        assert!(path.exists());
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "aevan-daemon-main-{label}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
