//! Decide how to make the registered macOS daemon available.
//!
//! The daemon is a system LaunchDaemon whose plist ships inside the app bundle.
//! macOS 13 and later register that plist through ServiceManagement's
//! `SMAppService`; the user approves it once in System Settings > Login Items &
//! Extensions. There are no administrator prompts and no elevated shell
//! commands in this path. Approval is surfaced as its own state and is never
//! retried silently.

use std::fmt;

/// The daemon registration state reported by `SMAppService.status()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    /// Registered and approved; macOS may launch it.
    Enabled,
    /// Registered, but an administrator must approve it in System Settings.
    RequiresApproval,
    /// The service has not been registered by this app.
    NotRegistered,
    /// The bundled plist could not be found.
    NotFound,
    /// The state could not be read on this platform or build.
    Unavailable(String),
}

impl ServiceState {
    /// A short label for the Settings sheet.
    pub fn label(&self) -> &str {
        match self {
            Self::Enabled => "enabled",
            Self::RequiresApproval => "requires approval in System Settings",
            Self::NotRegistered => "not registered",
            Self::NotFound => "not found",
            Self::Unavailable(reason) => reason,
        }
    }

    /// Whether macOS waits for the user to approve the daemon.
    pub fn requires_approval(&self) -> bool {
        matches!(self, Self::RequiresApproval)
    }

    /// Whether the service is currently registered with ServiceManagement.
    pub fn is_registered(&self) -> bool {
        matches!(self, Self::Enabled | Self::RequiresApproval)
    }
}

impl fmt::Display for ServiceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// The exact guidance shown when approval is outstanding.
pub const APPROVAL_REQUIRED_MESSAGE: &str = "The Aevan daemon is registered but needs approval. Open System Settings > Login Items & Extensions, enable Aevan, then try again.";

/// The exact guidance shown when the bundled plist is missing.
pub const NOT_FOUND_MESSAGE: &str =
    "The Aevan daemon plist is missing from the app bundle. Reinstall Aevan and try again.";

/// How the daemon was made available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMethod {
    /// The control socket already answered; nothing was started.
    AlreadyRunning,
    /// The service was registered and became enabled.
    Registered,
    /// An enabled service was asked to start again.
    Kickstarted,
}

/// The result of a start decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartReport {
    /// What happened.
    pub method: StartMethod,
}

/// The platform operations a start needs.
///
/// Implementations perform real work; tests inject a fake and assert that an
/// approval state never leads to a registration retry or a kickstart.
pub trait RelaunchOps {
    /// Whether the control socket answers a status probe.
    fn socket_answers(&self) -> bool;

    /// Read the current `SMAppService` status.
    fn service_status(&self) -> Result<ServiceState, String>;

    /// Register the bundled LaunchDaemon. Already-registered is success.
    fn register(&self) -> Result<(), String>;

    /// Ask an enabled service to start again.
    fn kickstart(&self) -> Result<(), String>;

    /// Wait until the control socket answers after a start.
    fn wait_ready(&self) -> Result<(), String>;
}

/// Run the ordered start decision.
pub fn relaunch(ops: &impl RelaunchOps) -> Result<StartReport, String> {
    if ops.socket_answers() {
        return Ok(StartReport {
            method: StartMethod::AlreadyRunning,
        });
    }

    match ops.service_status()? {
        ServiceState::Enabled => {
            // The daemon is approved. A kickstart is best-effort; the socket
            // answering is the proof that it is ready.
            let _ = ops.kickstart();
            ops.wait_ready()?;
            Ok(StartReport {
                method: StartMethod::Kickstarted,
            })
        }
        ServiceState::RequiresApproval => Err(APPROVAL_REQUIRED_MESSAGE.to_owned()),
        ServiceState::NotRegistered => {
            ops.register()?;
            match ops.service_status()? {
                ServiceState::Enabled => {
                    let _ = ops.kickstart();
                    ops.wait_ready()?;
                    Ok(StartReport {
                        method: StartMethod::Registered,
                    })
                }
                ServiceState::RequiresApproval => Err(APPROVAL_REQUIRED_MESSAGE.to_owned()),
                ServiceState::NotFound => Err(NOT_FOUND_MESSAGE.to_owned()),
                other => Err(format!(
                    "the Aevan daemon was registered but reports {other}"
                )),
            }
        }
        ServiceState::NotFound => Err(NOT_FOUND_MESSAGE.to_owned()),
        ServiceState::Unavailable(reason) => Err(reason),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use super::*;

    #[derive(Default)]
    struct Fake {
        socket_answers: bool,
        states: RefCell<VecDeque<ServiceState>>,
        register_error: Option<String>,
        sockets: Cell<usize>,
        statuses: Cell<usize>,
        registers: Cell<usize>,
        kickstarts: Cell<usize>,
        waits: Cell<usize>,
    }

    impl Fake {
        fn with_states(states: impl IntoIterator<Item = ServiceState>) -> Self {
            Self {
                states: RefCell::new(states.into_iter().collect()),
                register_error: None,
                ..Self::default()
            }
        }
    }

    impl RelaunchOps for Fake {
        fn socket_answers(&self) -> bool {
            self.sockets.set(self.sockets.get() + 1);
            self.socket_answers
        }

        fn service_status(&self) -> Result<ServiceState, String> {
            self.statuses.set(self.statuses.get() + 1);
            self.states
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| "the fake has no status left".to_owned())
        }

        fn register(&self) -> Result<(), String> {
            self.registers.set(self.registers.get() + 1);
            match &self.register_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn kickstart(&self) -> Result<(), String> {
            self.kickstarts.set(self.kickstarts.get() + 1);
            Ok(())
        }

        fn wait_ready(&self) -> Result<(), String> {
            self.waits.set(self.waits.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn an_answering_socket_is_used_with_no_action() {
        let fake = Fake {
            socket_answers: true,
            ..Fake::default()
        };
        let report = relaunch(&fake).expect("relaunch");
        assert_eq!(report.method, StartMethod::AlreadyRunning);
        assert_eq!(fake.sockets.get(), 1);
        assert_eq!(fake.statuses.get(), 0);
        assert_eq!(fake.registers.get(), 0);
        assert_eq!(fake.kickstarts.get(), 0);
        assert_eq!(fake.waits.get(), 0);
    }

    #[test]
    fn an_enabled_service_is_kickstarted_without_elevation() {
        let fake = Fake::with_states([ServiceState::Enabled]);
        let report = relaunch(&fake).expect("relaunch");
        assert_eq!(report.method, StartMethod::Kickstarted);
        assert_eq!(fake.registers.get(), 0);
        assert_eq!(fake.kickstarts.get(), 1);
        assert_eq!(fake.waits.get(), 1);
    }

    #[test]
    fn approval_is_reported_and_never_retried() {
        let fake = Fake::with_states([ServiceState::RequiresApproval]);
        let error = relaunch(&fake).expect_err("approval is outstanding");
        assert!(error.contains("System Settings > Login Items & Extensions"));
        assert_eq!(fake.registers.get(), 0);
        assert_eq!(fake.kickstarts.get(), 0);
        assert_eq!(fake.waits.get(), 0);
    }

    #[test]
    fn an_unregistered_service_is_registered_once_and_waits_for_approval() {
        let fake = Fake::with_states([ServiceState::NotRegistered, ServiceState::RequiresApproval]);
        let error = relaunch(&fake).expect_err("approval is outstanding");
        assert!(error.contains("System Settings > Login Items & Extensions"));
        assert_eq!(fake.registers.get(), 1);
        assert_eq!(fake.kickstarts.get(), 0);
        assert_eq!(fake.waits.get(), 0);
    }

    #[test]
    fn registration_that_becomes_enabled_starts_the_daemon() {
        let fake = Fake::with_states([ServiceState::NotRegistered, ServiceState::Enabled]);
        let report = relaunch(&fake).expect("relaunch");
        assert_eq!(report.method, StartMethod::Registered);
        assert_eq!(fake.registers.get(), 1);
        assert_eq!(fake.kickstarts.get(), 1);
        assert_eq!(fake.waits.get(), 1);
    }

    #[test]
    fn a_missing_plist_is_named_and_not_registered() {
        let fake = Fake::with_states([ServiceState::NotFound]);
        let error = relaunch(&fake).expect_err("the plist is missing");
        assert!(error.contains("missing from the app bundle"));
        assert_eq!(fake.registers.get(), 0);
    }

    #[test]
    fn an_unreadable_status_is_returned_verbatim() {
        let fake = Fake::with_states([ServiceState::Unavailable("no ServiceManagement".into())]);
        assert_eq!(
            relaunch(&fake).expect_err("unavailable"),
            "no ServiceManagement"
        );
        assert_eq!(fake.registers.get(), 0);
    }
}
