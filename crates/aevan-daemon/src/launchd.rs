//! The macOS system LaunchDaemon that owns the root `aevand` process.
//!
//! The daemon is installed once. After that launchd starts it at boot and
//! restarts it if it exits, so the GUI never needs another administrator
//! prompt and Quit never has to stop a machine-wide service.
//!
//! The plist text is built (and tested) on every platform; only `install`,
//! `kickstart` and `is_installed` talk to launchd on macOS.

use std::path::Path;

/// Reverse-DNS launchd label for the daemon.
pub const LABEL: &str = "com.github.kilisk.aevand";

/// Installed plist path.
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.github.kilisk.aevand.plist";

/// Build the LaunchDaemon plist for `program`.
///
/// `RunAtLoad` and `KeepAlive` are both true: a reboot starts the daemon with
/// no prompt, and launchd restarts it if it exits.
pub fn plist(program: &Path) -> String {
    let program = xml_escape(&program.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{program}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HOME</key>
		<string>/var/root</string>
	</dict>
	<key>StandardOutPath</key>
	<string>/var/log/aevand.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/aevand.log</string>
</dict>
</plist>
"#
    )
}

fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Whether the daemon job is already installed (plist present or loaded).
#[cfg(target_os = "macos")]
pub fn is_installed() -> bool {
    imp::is_installed()
}

#[cfg(not(target_os = "macos"))]
pub fn is_installed() -> bool {
    false
}

/// The exact command used to kickstart the installed job as the current user.
pub fn kickstart_command() -> String {
    format!("/bin/launchctl kickstart -k system/{LABEL}")
}

#[cfg(target_os = "macos")]
pub fn install(program: &Path) -> Result<(), String> {
    imp::install(program)
}

#[cfg(not(target_os = "macos"))]
pub fn install(_program: &Path) -> Result<(), String> {
    Err("installing a LaunchDaemon is only implemented on macOS".into())
}

/// Install the LaunchDaemon and report the exact command, status and stderr so
/// the GUI can write its owner-only start log.
#[cfg(target_os = "macos")]
pub fn install_detailed(program: &Path) -> crate::elevate::ScriptOutcome {
    imp::install_detailed(program)
}

#[cfg(not(target_os = "macos"))]
pub fn install_detailed(_program: &Path) -> crate::elevate::ScriptOutcome {
    crate::elevate::ScriptOutcome {
        command: String::new(),
        outcome: crate::elevate::StartOutcome::Failed(
            "installing a LaunchDaemon is only implemented on macOS".into(),
        ),
        exit_status: None,
        stderr: String::new(),
    }
}

#[cfg(target_os = "macos")]
pub fn kickstart() -> Result<(), String> {
    imp::kickstart()
}

#[cfg(not(target_os = "macos"))]
pub fn kickstart() -> Result<(), String> {
    Err("starting a LaunchDaemon is only implemented on macOS".into())
}

/// Re-arm the installed job behind the single admin prompt: bootstrap it if it
/// is not loaded, then kickstart it. Used only when the unelevated kickstart is
/// refused.
#[cfg(target_os = "macos")]
pub fn rearm_detailed() -> crate::elevate::ScriptOutcome {
    imp::rearm_detailed()
}

#[cfg(not(target_os = "macos"))]
pub fn rearm_detailed() -> crate::elevate::ScriptOutcome {
    crate::elevate::ScriptOutcome {
        command: String::new(),
        outcome: crate::elevate::StartOutcome::Failed(
            "starting a LaunchDaemon is only implemented on macOS".into(),
        ),
        exit_status: None,
        stderr: String::new(),
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::Command;

    use crate::elevate::{self, StartOutcome};

    use super::{plist, LABEL, PLIST_PATH};

    fn posix_quote(value: &OsStr) -> String {
        let text = value.to_string_lossy();
        let mut quoted = String::with_capacity(text.len() + 2);
        quoted.push('\'');
        for character in text.chars() {
            if character == '\'' {
                quoted.push_str("'\''");
            } else {
                quoted.push(character);
            }
        }
        quoted.push('\'');
        quoted
    }

    pub fn is_installed() -> bool {
        if std::path::Path::new(PLIST_PATH).is_file() {
            return true;
        }
        Command::new("/bin/launchctl")
            .args(["print", &format!("system/{LABEL}")])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    pub fn install(program: &Path) -> Result<(), String> {
        outcome_result(install_detailed(program).outcome)
    }

    pub fn install_detailed(program: &Path) -> elevate::ScriptOutcome {
        let contents = plist(program);
        let temporary =
            std::env::temp_dir().join(format!("aevan-{LABEL}-{}.plist", std::process::id()));
        if let Err(error) = std::fs::write(&temporary, contents) {
            let message = format!("could not stage the LaunchDaemon plist: {error}");
            return elevate::ScriptOutcome {
                command: String::new(),
                outcome: StartOutcome::Failed(message.clone()),
                exit_status: None,
                stderr: message,
            };
        }

        let script = format!(
            "/usr/bin/install -m 0644 -o root -g wheel {} {} && /bin/launchctl bootstrap system {}",
            posix_quote(temporary.as_os_str()),
            posix_quote(OsStr::new(PLIST_PATH)),
            posix_quote(OsStr::new(PLIST_PATH)),
        );
        let outcome = elevate::run_script_elevated_captured(&script);
        let _ = std::fs::remove_file(&temporary);
        outcome
    }

    pub fn rearm_detailed() -> elevate::ScriptOutcome {
        // `bootstrap` may fail when the job is already loaded; the kickstart
        // after it still runs, and its status is the reported one.
        let script = format!(
            "/bin/launchctl bootstrap system {} 2>/dev/null || true; {}",
            posix_quote(OsStr::new(PLIST_PATH)),
            super::kickstart_command()
        );
        elevate::run_script_elevated_captured(&script)
    }

    fn outcome_result(outcome: StartOutcome) -> Result<(), String> {
        match outcome {
            StartOutcome::Started => Ok(()),
            StartOutcome::Cancelled => Err(
                "installing the Aevan daemon needs administrator approval; the prompt was dismissed"
                    .into(),
            ),
            StartOutcome::Failed(message) => Err(message),
        }
    }

    pub fn kickstart() -> Result<(), String> {
        let output = Command::new("/bin/launchctl")
            .args(["kickstart", "-k", &format!("system/{LABEL}")])
            .output()
            .map_err(|error| format!("could not run launchctl kickstart: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        Err(if detail.is_empty() {
            format!(
                "launchctl kickstart system/{LABEL} failed with {}",
                output.status
            )
        } else {
            format!("launchctl kickstart system/{LABEL} failed: {detail}")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plist_uses_the_application_daemon_and_stays_alive() {
        let text = plist(Path::new("/Applications/Aevan.app/Contents/MacOS/aevand"));
        assert!(text.contains("<string>com.github.kilisk.aevand</string>"));
        assert!(text.contains("<string>/Applications/Aevan.app/Contents/MacOS/aevand</string>"));
        assert!(text.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(text.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(!text.contains("<key>SuccessfulExit</key>"));
        // launchd gives system daemons no HOME; the plist supplies one so any
        // remaining $HOME lookup cannot fail the daemon at startup.
        assert!(text.contains("<key>EnvironmentVariables</key>"));
        assert!(text.contains(
            "<key>HOME</key>
		<string>/var/root</string>"
        ));
    }

    #[test]
    fn the_plist_escapes_xml_in_the_program_path() {
        let text = plist(Path::new(
            "/Applications/A&B/Aevan.app/Contents/MacOS/aevand",
        ));
        assert!(text.contains("/Applications/A&amp;B/Aevan.app"));
        assert!(!text.contains("A&B/Aevan"));
    }

    #[test]
    fn the_installed_path_is_the_documented_one() {
        assert_eq!(
            PLIST_PATH,
            "/Library/LaunchDaemons/com.github.kilisk.aevand.plist"
        );
    }
}
