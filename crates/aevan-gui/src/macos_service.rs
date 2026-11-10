//! macOS daemon registration through ServiceManagement.
//!
//! The LaunchDaemon plist ships inside the app bundle at
//! `Contents/Library/LaunchDaemons/com.github.kilisk.aevand.plist`. macOS 13
//! and later register that plist with `SMAppService.daemon(plistName:)`; the
//! user approves the daemon in System Settings > Login Items & Extensions.
//! Registration is idempotent: an already-registered service is success, and
//! unregistering an absent service is success.

use crate::relaunch::{ServiceState, APPROVAL_REQUIRED_MESSAGE, NOT_FOUND_MESSAGE};

/// File name of the bundled LaunchDaemon plist.
pub const PLIST_NAME: &str = "com.github.kilisk.aevand.plist";

/// Read the current `SMAppService` status.
pub fn status() -> Result<ServiceState, String> {
    imp::status()
}

/// Register the bundled LaunchDaemon. Already registered is success.
pub fn register() -> Result<(), String> {
    imp::register()
}

/// Unregister the daemon. Already unregistered is success.
pub fn unregister() -> Result<(), String> {
    imp::unregister()
}

/// Open System Settings at Login Items & Extensions.
pub fn open_login_items() {
    imp::open_login_items();
}

// Objective-C interop lives in this macOS-only module so the GUI crate keeps
// `#![deny(unsafe_code)]` everywhere else. Framework: ServiceManagement.
// Calls: SMAppService.daemonService(plistName:), status(),
// registerAndReturnError(), unregisterAndReturnError() and
// openSystemSettingsLoginItems().
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod imp {
    use objc2_foundation::{NSError, NSString};
    use objc2_service_management::{
        kSMErrorAlreadyRegistered, kSMErrorJobNotFound, kSMErrorJobPlistNotFound,
        kSMErrorLaunchDeniedByUser, SMAppService, SMAppServiceStatus,
    };

    use crate::relaunch::ServiceState;

    use super::PLIST_NAME;

    fn service() -> objc2::rc::Retained<SMAppService> {
        let plist_name = NSString::from_str(PLIST_NAME);
        // SAFETY: `daemonServiceWithPlistName:` only reads the string for the
        // duration of the call and returns a retained service object.
        unsafe { SMAppService::daemonServiceWithPlistName(&plist_name) }
    }

    pub(super) fn status() -> Result<ServiceState, String> {
        let service = service();
        // SAFETY: `status` has no preconditions and does not retain anything.
        let status = unsafe { service.status() };
        Ok(if status == SMAppServiceStatus::Enabled {
            ServiceState::Enabled
        } else if status == SMAppServiceStatus::RequiresApproval {
            ServiceState::RequiresApproval
        } else if status == SMAppServiceStatus::NotRegistered {
            ServiceState::NotRegistered
        } else {
            ServiceState::NotFound
        })
    }

    pub(super) fn register() -> Result<(), String> {
        if matches!(
            status()?,
            ServiceState::Enabled | ServiceState::RequiresApproval
        ) {
            return Ok(());
        }

        let service = service();
        // SAFETY: `registerAndReturnError:` has no preconditions; the returned
        // error is retained by the binding on failure.
        match unsafe { service.registerAndReturnError() } {
            Ok(()) => Ok(()),
            Err(error) => match error.code() {
                code if code == kSMErrorAlreadyRegistered as isize => Ok(()),
                code if code == kSMErrorLaunchDeniedByUser as isize => {
                    Err(APPROVAL_REQUIRED_MESSAGE.to_owned())
                }
                code if code == kSMErrorJobPlistNotFound as isize => {
                    Err(NOT_FOUND_MESSAGE.to_owned())
                }
                _ => Err(describe(&error)),
            },
        }
    }

    pub(super) fn unregister() -> Result<(), String> {
        if matches!(
            status()?,
            ServiceState::NotRegistered | ServiceState::NotFound
        ) {
            return Ok(());
        }

        let service = service();
        // SAFETY: `unregisterAndReturnError:` has no preconditions; the
        // returned error is retained by the binding on failure.
        match unsafe { service.unregisterAndReturnError() } {
            Ok(()) => Ok(()),
            Err(error) if error.code() == kSMErrorJobNotFound as isize => Ok(()),
            Err(error) => Err(describe(&error)),
        }
    }

    pub(super) fn open_login_items() {
        // SAFETY: opens the System Settings pane; it has no preconditions and
        // does not touch the calling app's state.
        unsafe { SMAppService::openSystemSettingsLoginItems() };
    }

    fn describe(error: &NSError) -> String {
        let description = error.localizedDescription();
        format!("ServiceManagement error {}: {description}", error.code())
    }
}
