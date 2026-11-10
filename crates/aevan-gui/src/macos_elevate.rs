//! The macOS administrator-approved fallback for unsigned builds.
//!
//! `SMAppService` requires a Developer ID signature: an ad-hoc signed build
//! (`codesign --sign -`) is refused with `kSMErrorInvalidSignature` or
//! "Operation not permitted" before the approval UI appears. The GUI therefore
//! falls back once to the legacy LaunchDaemon install that works unsigned:
//! write `/Library/LaunchDaemons/com.github.kilisk.aevand.plist` and run
//! `launchctl bootstrap` through one native administrator prompt.
//!
//! The prompt is `/usr/bin/osascript` started as a child process, never an
//! in-process AppleScript bridge, so a prompt failure cannot crash the window.
//! The script is built by the pure quoting functions below and unit tested.
//! This module is the only place in the GUI allowed to name osascript; remove
//! the fallback once the app is Developer ID signed, because `SMAppService`
//! then works and no prompt is needed.

use std::path::Path;

use aevan_daemon::launchd;

/// Absolute path of the legacy system LaunchDaemon installed by the fallback.
pub const INSTALLED_PLIST: &str = "/Library/LaunchDaemons/com.github.kilisk.aevand.plist";

/// The exact message shown when the administrator prompt is cancelled.
pub const CANCELLED_MESSAGE: &str =
    "The helper was not installed. Aevan needs administrator approval once.";

/// Whether a ServiceManagement failure should use the legacy fallback.
///
/// Approval outstanding is the one condition that must not fall back: the
/// service is registered and the user must approve it in System Settings.
/// Every other failure — including `kSMErrorInvalidSignature` and
/// "Operation not permitted" from an ad-hoc signed build — uses the fallback.
pub fn should_fall_back(error: &str) -> bool {
    error != crate::relaunch::APPROVAL_REQUIRED_MESSAGE
}

/// Whether the legacy helper plist is already installed.
///
/// Once it exists, the daemon is a normal LaunchDaemon with `RunAtLoad`; later
/// launches must not prompt again.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn daemon_installed() -> bool {
    Path::new(INSTALLED_PLIST).is_file()
}

/// Render the legacy plist with an absolute daemon program path.
///
/// The bundled plist uses `BundleProgram`, which only resolves inside the app
/// bundle; a copy in `/Library/LaunchDaemons` needs `ProgramArguments`.
pub fn legacy_plist(daemon: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{daemon}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HOME</key>
		<string>/var/root</string>
	</dict>
</dict>
</plist>
"#,
        label = xml_escape(launchd::LABEL),
        daemon = xml_escape(&daemon.to_string_lossy()),
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Quote one string as a POSIX shell word.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Quote one string as an AppleScript double-quoted literal.
pub fn applescript_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// Build the one AppleScript statement that installs and bootstraps the helper.
pub fn install_script(plist_contents: &str) -> String {
    let install = format!(
        "/bin/mkdir -p {directory} && /usr/bin/printf '%s' {contents} > {plist} && /usr/sbin/chown root:wheel {plist} && /bin/chmod 0644 {plist} && /bin/launchctl bootstrap system {plist}",
        directory = shell_quote("/Library/LaunchDaemons"),
        contents = shell_quote(plist_contents),
        plist = shell_quote(INSTALLED_PLIST),
    );
    format!(
        "do shell script {} with administrator privileges",
        applescript_quote(&install)
    )
}

/// Run one shell script through the native administrator prompt.
///
/// This is the single elevation path shared with the daemon fallback and the
/// command-line tool links. `osascript` is a child process: a crash or a
/// cancelled prompt is an error result, never a crash of the GUI.
#[cfg(target_os = "macos")]
pub fn run_with_administrator(script: &str, failure: &str) -> Result<(), String> {
    let applescript = format!(
        "do shell script {} with administrator privileges",
        applescript_quote(script)
    );
    let output = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(applescript)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|error| format!("could not ask macOS for administrator approval: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    if is_cancelled(detail) {
        return Err(CANCELLED_MESSAGE.to_owned());
    }
    Err(if detail.is_empty() {
        format!("{failure} (osascript exited with {})", output.status)
    } else {
        format!("{failure}: {detail}")
    })
}

/// Ask macOS for one administrator prompt and install the legacy LaunchDaemon.
#[cfg(target_os = "macos")]
pub fn install(daemon: &Path) -> Result<(), String> {
    run_with_administrator(
        &legacy_install_command(daemon),
        "the administrator approval did not install the Aevan helper",
    )
}

/// The inner shell command that writes and bootstraps the legacy plist.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn legacy_install_command(daemon: &Path) -> String {
    let plist_contents = legacy_plist(daemon);
    format!(
        "/bin/mkdir -p {directory} && /usr/bin/printf '%s' {contents} > {plist} && /usr/sbin/chown root:wheel {plist} && /bin/chmod 0644 {plist} && /bin/launchctl bootstrap system {plist}",
        directory = shell_quote("/Library/LaunchDaemons"),
        contents = shell_quote(&plist_contents),
        plist = shell_quote(INSTALLED_PLIST),
    )
}

fn is_cancelled(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("user canceled")
        || lower.contains("user cancelled")
        || lower.contains("(-128)")
        || lower.contains("-128")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relaunch::APPROVAL_REQUIRED_MESSAGE;

    #[test]
    fn a_posix_shell_word_is_single_quoted_and_escapes_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(shell_quote("a b\nc"), "'a b\nc'");
    }

    #[test]
    fn an_applescript_literal_escapes_quotes_backslashes_and_newlines() {
        assert_eq!(applescript_quote("plain"), "\"plain\"");
        assert_eq!(applescript_quote("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    }

    #[test]
    fn the_install_script_names_one_admin_prompt_and_the_legacy_path() {
        let script = install_script("<plist>a & b</plist>");
        assert!(script.starts_with("do shell script \""));
        assert!(script.ends_with(" with administrator privileges"));
        assert!(script.contains("/bin/launchctl bootstrap system"));
        assert!(script.contains(INSTALLED_PLIST));
        assert!(script.contains("/usr/sbin/chown root:wheel"));
        assert!(script.contains("a & b"));
    }

    #[test]
    fn the_legacy_plist_uses_an_absolute_program_path_and_run_at_load() {
        let plist = legacy_plist(Path::new(
            "/Applications/Aevan & Co.app/Contents/MacOS/aevand",
        ));
        assert!(plist.contains("<string>com.github.kilisk.aevand</string>"));
        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist
            .contains("<string>/Applications/Aevan &amp; Co.app/Contents/MacOS/aevand</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(!plist.contains("BundleProgram"));
    }

    #[test]
    fn approval_is_the_only_failure_that_does_not_fall_back() {
        assert!(!should_fall_back(APPROVAL_REQUIRED_MESSAGE));
        assert!(should_fall_back(
            "ServiceManagement error 1: The operation couldn't be completed. Operation not permitted"
        ));
        assert!(should_fall_back("the bundled plist is missing"));
    }

    #[test]
    fn cancellation_is_recognized_in_osascript_output() {
        assert!(CANCELLED_MESSAGE.contains("administrator approval once"));
        assert!(is_cancelled("execution error: User canceled. (-128)"));
        assert!(is_cancelled("User cancelled."));
        assert!(!is_cancelled("launchctl: permission denied"));
    }
}
