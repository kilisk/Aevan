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

#[cfg(target_os = "macos")]
pub fn install(program: &Path) -> Result<(), String> {
    imp::install(program)
}

#[cfg(not(target_os = "macos"))]
pub fn install(_program: &Path) -> Result<(), String> {
    Err("installing a LaunchDaemon is only implemented on macOS".into())
}

#[cfg(target_os = "macos")]
pub fn kickstart() -> Result<(), String> {
    imp::kickstart()
}

#[cfg(not(target_os = "macos"))]
pub fn kickstart() -> Result<(), String> {
    Err("starting a LaunchDaemon is only implemented on macOS".into())
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
        let contents = plist(program);
        let temporary =
            std::env::temp_dir().join(format!("aevan-{LABEL}-{}.plist", std::process::id()));
        std::fs::write(&temporary, contents)
            .map_err(|error| format!("could not stage the LaunchDaemon plist: {error}"))?;

        let script = format!(
            "/usr/bin/install -m 0644 -o root -g wheel {} {} && /bin/launchctl bootstrap system {}",
            posix_quote(temporary.as_os_str()),
            posix_quote(OsStr::new(PLIST_PATH)),
            posix_quote(OsStr::new(PLIST_PATH)),
        );
        let outcome = elevate::run_script_elevated(&script);
        let _ = std::fs::remove_file(&temporary);

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
