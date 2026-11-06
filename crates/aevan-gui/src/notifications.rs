//! Desktop notifications behind a trait.
//!
//! The view model decides *what* a transition should say; this module is the
//! only place that talks to the operating system. Tests use a recording
//! notifier, so the assertion runs offline without a notification daemon.
//!
//! Notification text is built exclusively from the state name, the assigned
//! tunnel address and the daemon's already-redacted failure reason. It never
//! receives a password, a one-time token or a TOTP secret.

use crate::view_model::TransitionNotification;

/// A sink for transition notifications.
pub trait Notifier {
    /// Show one notification.
    fn notify(&self, notification: &TransitionNotification);
}

/// The real desktop notifier (`notify-rust`; Windows toast backend).
pub struct DesktopNotifier;

impl Notifier for DesktopNotifier {
    fn notify(&self, notification: &TransitionNotification) {
        // A notification is best-effort: a desktop without a notification
        // service must never take the GUI down. The tray tooltip keeps the
        // current state visible either way.
        let body = notification.body();
        let _ = notify_rust::Notification::new()
            .summary(notification.title())
            .body(&body)
            .show();
    }
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
