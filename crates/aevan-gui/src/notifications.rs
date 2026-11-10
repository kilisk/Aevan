//! Desktop notifications behind a trait.
//!
//! The view model decides *what* a transition should say; this module is the
//! only place that talks to the operating system. Tests use a recording
//! notifier, so the assertion runs offline without a notification daemon.
//!
//! Notification text is built exclusively from the state name, the assigned
//! tunnel address and the daemon's already-redacted failure reason. It never
//! receives a password, a one-time token or a TOTP secret.
//!
//! Windows and Linux use `notify-rust`. macOS uses UserNotifications directly:
//! authorization is requested once at startup for alert and sound, and each
//! transition is delivered as a `UNNotificationRequest` with a nil trigger.
//! There is no scripting bridge and no shell quoting anywhere.

use crate::view_model::TransitionNotification;

/// A sink for transition notifications.
pub trait Notifier {
    /// Show one notification.
    fn notify(&self, notification: &TransitionNotification);
}

/// The real desktop notifier.
pub struct DesktopNotifier;

impl Notifier for DesktopNotifier {
    fn notify(&self, notification: &TransitionNotification) {
        // A notification is best-effort: a desktop without a notification
        // service or a denied authorization must never take the GUI down. The
        // tray tooltip keeps the current state visible either way. The caller
        // additionally catches a panic from this path.
        if let Err(error) = deliver(notification) {
            tracing::warn!(%error, "desktop notification could not be shown");
        }
    }
}

/// The macOS authorization result recorded at startup.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// The user allowed alerts and sound.
    Granted,
    /// The user denied notifications, or System Settings disables them.
    Denied,
    /// The request did not finish before the bounded wait expired.
    Unknown,
}

/// Request notification authorization once at startup.
#[cfg(target_os = "macos")]
pub fn request_authorization() -> Authorization {
    macos::request_authorization()
}

#[cfg(target_os = "macos")]
fn deliver(notification: &TransitionNotification) -> Result<(), String> {
    macos::deliver(notification.title(), &notification.body())
}

#[cfg(not(target_os = "macos"))]
fn deliver(notification: &TransitionNotification) -> Result<(), String> {
    let body = notification.body();
    notify_rust::Notification::new()
        .summary(notification.title())
        .body(&body)
        .show()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// A notifier that records notifications instead of showing them.
#[cfg(test)]
#[derive(Default)]
pub struct RecordingNotifier {
    shown: std::cell::RefCell<Vec<TransitionNotification>>,
}

#[cfg(test)]
impl RecordingNotifier {
    /// All notifications recorded so far.
    pub fn shown(&self) -> Vec<TransitionNotification> {
        self.shown.borrow().clone()
    }
}

#[cfg(test)]
impl Notifier for RecordingNotifier {
    fn notify(&self, notification: &TransitionNotification) {
        self.shown.borrow_mut().push(notification.clone());
    }
}

// Objective-C interop lives in this macOS-only module so the GUI crate keeps
// `#![deny(unsafe_code)]` everywhere else. Framework: UserNotifications.
// Calls: UNUserNotificationCenter.requestAuthorization(options:completionHandler:)
// and addNotificationRequest(_:withCompletionHandler:).
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos {
    use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_user_notifications::{
        UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
        UNNotificationSound, UNUserNotificationCenter,
    };

    use super::Authorization;

    const UNKNOWN: u8 = 0;
    const GRANTED: u8 = 1;
    const DENIED: u8 = 2;

    static AUTHORIZATION: AtomicU8 = AtomicU8::new(UNKNOWN);
    static NEXT_IDENTIFIER: AtomicU64 = AtomicU64::new(0);

    pub(super) fn request_authorization() -> Authorization {
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let options = UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound;

        // The completion handler runs asynchronously on a system queue. A
        // bounded channel wait keeps this call synchronous for the startup
        // worker without blocking the window thread.
        let (sender, receiver) = mpsc::channel();
        let completion = RcBlock::new(move |granted: Bool, _error: *mut NSError| {
            let _ = sender.send(granted.as_bool());
        });
        center.requestAuthorizationWithOptions_completionHandler(options, &completion);

        let authorization = match receiver.recv_timeout(Duration::from_secs(120)) {
            Ok(true) => Authorization::Granted,
            Ok(false) => Authorization::Denied,
            Err(_) => Authorization::Unknown,
        };
        AUTHORIZATION.store(
            match authorization {
                Authorization::Granted => GRANTED,
                Authorization::Denied => DENIED,
                Authorization::Unknown => UNKNOWN,
            },
            Ordering::Relaxed,
        );
        authorization
    }

    pub(super) fn deliver(title: &str, body: &str) -> Result<(), String> {
        if AUTHORIZATION.load(Ordering::Relaxed) == DENIED {
            return Err("notifications are disabled in System Settings".to_owned());
        }

        let center = UNUserNotificationCenter::currentNotificationCenter();
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(title));
        content.setBody(&NSString::from_str(body));
        content.setSound(Some(&UNNotificationSound::defaultSound()));

        let identifier = NSString::from_str(&format!(
            "com.github.kilisk.aevan.transition.{}",
            next_identifier()
        ));
        let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &identifier,
            &content,
            None,
        );
        center.addNotificationRequest_withCompletionHandler(&request, None);
        Ok(())
    }

    fn next_identifier() -> u64 {
        let counter = NEXT_IDENTIFIER.fetch_add(1, Ordering::Relaxed);
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        millis.wrapping_shl(16) | (counter & 0xffff)
    }
}

#[cfg(test)]
mod tests {
    use super::{Notifier, RecordingNotifier};
    use crate::view_model::TransitionNotification;

    #[test]
    fn the_recording_notifier_keeps_each_transition_once() {
        let notifier = RecordingNotifier::default();
        notifier.notify(&TransitionNotification::Connected {
            address: "10.0.0.1/32".into(),
        });
        notifier.notify(&TransitionNotification::Failed {
            reason: "denied".into(),
        });

        let shown = notifier.shown();
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0].title(), "Aevan connected");
        assert_eq!(shown[1].body(), "denied");
    }
}
