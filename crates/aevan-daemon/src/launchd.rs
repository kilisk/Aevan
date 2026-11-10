//! The macOS system LaunchDaemon that owns the root `aevand` process.
//!
//! The daemon plist ships inside the app bundle at
//! `Contents/Library/LaunchDaemons/com.github.kilisk.aevand.plist`. macOS 13
//! and later register that plist through ServiceManagement; this module only
//! names the job and can ask launchd to start an approved job again.
//!
//! The packaged plist is checked by the tests so the bundle layout and the
//! job label cannot drift.

/// Reverse-DNS launchd label for the daemon.
pub const LABEL: &str = "com.github.kilisk.aevand";

/// File name of the bundled LaunchDaemon plist.
pub const PLIST_NAME: &str = "com.github.kilisk.aevand.plist";

/// The exact command used to kickstart an approved job as the current user.
pub fn kickstart_command() -> String {
    format!("/bin/launchctl kickstart -k system/{LABEL}")
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
    use std::process::Command;

    use super::LABEL;

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

    const BUNDLED_PLIST: &str =
        include_str!("../../../packaging/macos/com.github.kilisk.aevand.plist");

    #[test]
    fn the_bundled_plist_names_the_application_daemon_and_stays_alive() {
        assert!(BUNDLED_PLIST.contains("<string>com.github.kilisk.aevand</string>"));
        assert!(BUNDLED_PLIST.contains("<key>BundleProgram</key>"));
        assert!(BUNDLED_PLIST.contains("<string>Contents/MacOS/aevand</string>"));
        assert!(BUNDLED_PLIST.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(BUNDLED_PLIST.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(!BUNDLED_PLIST.contains("<key>SuccessfulExit</key>"));
        assert!(!BUNDLED_PLIST.contains("<key>ProgramArguments</key>"));
        // launchd gives system daemons no HOME; the plist supplies one so any
        // remaining $HOME lookup cannot fail the daemon at startup.
        assert!(BUNDLED_PLIST.contains("<key>EnvironmentVariables</key>"));
        assert!(BUNDLED_PLIST.contains(
            "<key>HOME</key>
		<string>/var/root</string>"
        ));
    }

    #[test]
    fn the_bundled_plist_file_name_is_the_launchd_label() {
        assert_eq!(PLIST_NAME, "com.github.kilisk.aevand.plist");
        assert!(PLIST_NAME.starts_with(LABEL));
    }

    #[test]
    fn the_macos_deployment_target_is_thirteen() {
        let info = include_str!("../../../packaging/macos/Info.plist.in");
        assert!(info.contains("<key>LSMinimumSystemVersion</key>\n\t<string>13.0</string>"));
    }
}
