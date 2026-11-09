//! Decide how to (re)start the daemon with the fewest prompts.
//!
//! The macOS daemon is a keepalive system LaunchDaemon. Once it is installed,
//! relaunching the GUI must not ask for a password: if the system socket
//! already answers, use it; if the job is installed but idle, ask `launchctl`
//! to kickstart it as the logged-in user. Only a job that is not installed, or
//! a kickstart that the normal user is not allowed to perform, falls back to
//! the single administrator prompt.

/// How the daemon was made available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMethod {
    /// The system socket already answered; nothing was started.
    AlreadyRunning,
    /// An installed job was kickstarted without elevation.
    Kickstarted,
    /// An installed job was kickstarted through the one admin prompt.
    KickstartedElevated,
    /// The one-time install ran through the one admin prompt.
    Installed,
}

/// The result of a relaunch decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartReport {
    /// What happened.
    pub method: StartMethod,
    /// Whether an administrator prompt was shown.
    pub prompted: bool,
}

/// The platform commands a relaunch needs.
///
/// Implementations perform real work; tests inject a fake and assert that no
/// elevation command runs on the no-prompt paths.
pub trait RelaunchOps {
    /// Whether the system (or per-user) control socket answers a status probe.
    fn socket_answers(&self) -> bool;

    /// Whether the LaunchDaemon plist/job is installed.
    fn daemon_installed(&self) -> bool;

    /// Kickstart the installed job without elevation.
    fn kickstart(&self) -> Result<(), String>;

    /// Kickstart the installed job through the single admin prompt.
    fn kickstart_elevated(&self) -> Result<(), String>;

    /// Install the LaunchDaemon through the single admin prompt.
    fn install_elevated(&self) -> Result<(), String>;

    /// Wait until the control socket answers after a start.
    fn wait_ready(&self) -> Result<(), String>;
}

/// Run the ordered relaunch decision.
pub fn relaunch(ops: &impl RelaunchOps) -> Result<StartReport, String> {
    if ops.socket_answers() {
        return Ok(StartReport {
            method: StartMethod::AlreadyRunning,
            prompted: false,
        });
    }

    if ops.daemon_installed() {
        if ops.kickstart().is_ok() {
            ops.wait_ready()?;
            return Ok(StartReport {
                method: StartMethod::Kickstarted,
                prompted: false,
            });
        }
        ops.kickstart_elevated()?;
        ops.wait_ready()?;
        return Ok(StartReport {
            method: StartMethod::KickstartedElevated,
            prompted: true,
        });
    }

    ops.install_elevated()?;
    ops.wait_ready()?;
    Ok(StartReport {
        method: StartMethod::Installed,
        prompted: true,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[derive(Default)]
    struct Fake {
        socket_answers: bool,
        installed: bool,
        kickstart_fails: bool,
        install_fails: bool,
        sockets: Cell<usize>,
        kickstarts: Cell<usize>,
        elevated_kickstarts: Cell<usize>,
        installs: Cell<usize>,
        waits: Cell<usize>,
    }

    impl RelaunchOps for Fake {
        fn socket_answers(&self) -> bool {
            self.sockets.set(self.sockets.get() + 1);
            self.socket_answers
        }

        fn daemon_installed(&self) -> bool {
            self.installed
        }

        fn kickstart(&self) -> Result<(), String> {
            self.kickstarts.set(self.kickstarts.get() + 1);
            if self.kickstart_fails {
                Err("launchctl kickstart: Operation not permitted".into())
            } else {
                Ok(())
            }
        }

        fn kickstart_elevated(&self) -> Result<(), String> {
            self.elevated_kickstarts
                .set(self.elevated_kickstarts.get() + 1);
            Ok(())
        }

        fn install_elevated(&self) -> Result<(), String> {
            self.installs.set(self.installs.get() + 1);
            if self.install_fails {
                Err("the prompt was dismissed".into())
            } else {
                Ok(())
            }
        }

        fn wait_ready(&self) -> Result<(), String> {
            self.waits.set(self.waits.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn an_answering_socket_is_used_with_no_action_and_no_prompt() {
        let fake = Fake {
            socket_answers: true,
            ..Fake::default()
        };
        let report = relaunch(&fake).expect("relaunch");
        assert_eq!(report.method, StartMethod::AlreadyRunning);
        assert!(!report.prompted);
        assert_eq!(fake.sockets.get(), 1);
        assert_eq!(fake.kickstarts.get(), 0);
        assert_eq!(fake.elevated_kickstarts.get(), 0);
        assert_eq!(fake.installs.get(), 0);
        assert_eq!(fake.waits.get(), 0);
    }

    #[test]
    fn an_installed_job_is_kickstarted_without_elevation_or_a_prompt() {
        let fake = Fake {
            installed: true,
            ..Fake::default()
        };
        let report = relaunch(&fake).expect("relaunch");
        assert_eq!(report.method, StartMethod::Kickstarted);
        assert!(!report.prompted);
        assert_eq!(fake.kickstarts.get(), 1);
        assert_eq!(fake.elevated_kickstarts.get(), 0);
        assert_eq!(fake.installs.get(), 0);
        assert_eq!(fake.waits.get(), 1);
    }

    #[test]
    fn a_refused_kickstart_falls_back_to_exactly_one_admin_prompt() {
        let fake = Fake {
            installed: true,
            kickstart_fails: true,
            ..Fake::default()
        };
        let report = relaunch(&fake).expect("relaunch");
        assert_eq!(report.method, StartMethod::KickstartedElevated);
        assert!(report.prompted);
        assert_eq!(fake.kickstarts.get(), 1);
        assert_eq!(fake.elevated_kickstarts.get(), 1);
        assert_eq!(fake.installs.get(), 0, "no reinstall when the job exists");
        assert_eq!(fake.waits.get(), 1);
    }

    #[test]
    fn a_missing_job_is_installed_with_exactly_one_admin_prompt() {
        let fake = Fake::default();
        let report = relaunch(&fake).expect("relaunch");
        assert_eq!(report.method, StartMethod::Installed);
        assert!(report.prompted);
        assert_eq!(fake.kickstarts.get(), 0);
        assert_eq!(fake.elevated_kickstarts.get(), 0);
        assert_eq!(fake.installs.get(), 1);
        assert_eq!(fake.waits.get(), 1);
    }

    #[test]
    fn a_dismissed_install_prompt_reports_the_failure_and_stops() {
        let fake = Fake {
            install_fails: true,
            ..Fake::default()
        };
        assert!(relaunch(&fake).is_err());
        assert_eq!(fake.installs.get(), 1);
        assert_eq!(fake.waits.get(), 0);
    }
}
