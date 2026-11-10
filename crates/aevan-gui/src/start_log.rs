//! The macOS daemon-start log.
//!
//! Every daemon start attempt records the operation, its exit status and any
//! error text in `$HOME/Library/Logs/Aevan/daemon-start.log`. The file is
//! owner-only (0600) inside an owner-only directory (0700), so a failed start
//! names itself in the GUI banner without exposing anything to other users.
//!
//! Only an operation name, an exit status and captured error text are written.
//! Credentials and the tunnel key block are never part of a daemon start, and
//! this module has no way to receive them.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Path of the log relative to `$HOME` on macOS.
pub const RELATIVE_PATH: &str = "Library/Logs/Aevan/daemon-start.log";

/// Number of trailing lines shown in the failure banner.
pub const BANNER_LINES: usize = 3;

/// The default log path on this platform.
///
/// Only macOS has this location; every other platform returns `None`, so a
/// Windows elevated start does not invent a `Library` directory.
pub fn default_path() -> Option<PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(RELATIVE_PATH))
}

/// One entry to append.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// Timestamp text, for example `2026-11-09T12:00:00Z`.
    pub timestamp: &'a str,
    /// The exact command that was run with administrator approval.
    pub command: &'a str,
    /// The process exit status when one was observed.
    pub exit_status: Option<i32>,
    /// Captured stderr, verbatim.
    pub stderr: &'a str,
}

/// Append one entry, creating the parent directory and file as needed.
///
/// The directory is 0700 and the file 0600 on Unix. A logging failure is
/// returned so callers can ignore it: a start must not fail because its
/// diagnostic could not be written.
pub fn append(path: &Path, entry: &Entry<'_>) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_mode(parent, 0o700)?;
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    set_mode(path, 0o600)?;

    writeln!(file, "{} aevan daemon start", entry.timestamp)?;
    writeln!(file, "command: {}", entry.command)?;
    match entry.exit_status {
        Some(status) => writeln!(file, "exit: {status}")?,
        None => writeln!(file, "exit: unknown")?,
    }
    writeln!(file, "stderr: {}", entry.stderr)?;
    Ok(())
}

/// Append one entry to the platform default log when it exists.
///
/// Returns the number of bytes requested by the write, or `None` when this
/// platform has no start log.
pub fn record_default(
    command: &str,
    exit_status: Option<i32>,
    stderr: &str,
) -> Option<io::Result<()>> {
    let path = default_path()?;
    let timestamp = utc_timestamp(now_unix());
    Some(append(
        &path,
        &Entry {
            timestamp: &timestamp,
            command,
            exit_status,
            stderr,
        },
    ))
}

/// The last `count` lines of a log, oldest first.
///
/// A missing file is an empty list: the first failed start has nothing to show
/// yet, and that must not become a second failure.
pub fn tail(path: &Path, count: usize) -> Vec<String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return Vec::new(),
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(count);
    lines[start..]
        .iter()
        .map(|line| (*line).to_owned())
        .collect()
}

/// The last `count` lines of the platform default log.
pub fn tail_default(count: usize) -> Vec<String> {
    default_path()
        .map(|path| tail(&path, count))
        .unwrap_or_default()
}

/// Format a start failure with the tail of the log, when there is one.
pub fn with_tail(message: impl Into<String>, lines: Vec<String>) -> String {
    let message = message.into();
    if lines.is_empty() {
        return message;
    }
    format!(
        "{message}\nlast {} lines of the daemon-start log:\n{}",
        lines.len(),
        lines.join("\n")
    )
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix timestamp, without a date dependency.
fn utc_timestamp(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = remainder / 3_600;
    let minute = (remainder % 3_600) / 60;
    let second = remainder % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert days since 1970-01-01 to a proleptic Gregorian date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year + i64::from(month <= 2);
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn temp_path() -> PathBuf {
        let unique = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "aevan-start-log-test-{}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir.join("Library/Logs/Aevan/daemon-start.log")
    }

    #[test]
    fn an_entry_records_timestamp_command_status_and_stderr() {
        let path = temp_path();
        append(
            &path,
            &Entry {
                timestamp: "2026-11-09T12:00:00Z",
                command: "/bin/launchctl kickstart -k system/com.github.kilisk.aevand",
                exit_status: Some(1),
                stderr: "Could not find service",
            },
        )
        .expect("write");

        let text = fs::read_to_string(&path).expect("read");
        assert!(text.contains("2026-11-09T12:00:00Z"));
        assert!(
            text.contains("command: /bin/launchctl kickstart -k system/com.github.kilisk.aevand")
        );
        assert!(text.contains("exit: 1"));
        assert!(text.contains("stderr: Could not find service"));
        let _ = fs::remove_dir_all(path.parent().expect("parent").parent().expect("parent"));
    }

    #[test]
    fn the_directory_and_file_are_owner_only_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let path = temp_path();
            append(
                &path,
                &Entry {
                    timestamp: "2026-11-09T12:00:00Z",
                    command: "true",
                    exit_status: Some(0),
                    stderr: "",
                },
            )
            .expect("write");

            let dir_mode = fs::metadata(path.parent().expect("parent"))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            let file_mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
            let _ = fs::remove_dir_all(path.parent().expect("parent").parent().expect("parent"));
        }
    }

    #[test]
    fn tail_returns_the_last_lines_and_missing_files_are_empty() {
        let path = temp_path();
        assert!(tail(&path, BANNER_LINES).is_empty());

        for index in 0..5 {
            append(
                &path,
                &Entry {
                    timestamp: "2026-11-09T12:00:00Z",
                    command: "true",
                    exit_status: Some(index),
                    stderr: "",
                },
            )
            .expect("write");
        }
        let lines = tail(&path, BANNER_LINES);
        assert_eq!(lines.len(), BANNER_LINES);
        assert!(lines[1].contains("exit: 4"), "{lines:?}");
        let _ = fs::remove_dir_all(path.parent().expect("parent").parent().expect("parent"));
    }

    #[test]
    fn a_failure_message_carries_the_tail_but_stays_empty_when_there_is_none() {
        assert_eq!(with_tail("boom", Vec::new()), "boom");
        let message = with_tail("boom", vec!["exit: 1".into(), "stderr: denied".into()]);
        assert!(message.starts_with("boom"));
        assert!(message.contains("exit: 1"));
        assert!(message.contains("stderr: denied"));
    }

    #[test]
    fn timestamps_are_utc_and_cross_a_day_boundary() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_timestamp(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(utc_timestamp(86_400), "1970-01-02T00:00:00Z");
    }
}
