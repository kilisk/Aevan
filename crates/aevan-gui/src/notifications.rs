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
//! On macOS this module never links `notify-rust` / `mac-notification-sys`:
//! that stack executes AppleScript in-process, and a malformed script can load
//! `com.apple.applescript.component` / `osax.standardadditions` and abort the
//! whole process. Instead the notification is delivered by `/usr/bin/osascript`
//! as a child process, so a refused or malformed notification cannot take the
//! GUI down. The script is built from a pure, unit-tested quoting function that
//! escapes quotes and backslashes and strips control characters.

use crate::view_model::TransitionNotification;

/// A sink for transition notifications.
pub trait Notifier {
    /// Show one notification.
    fn notify(&self, notification: &TransitionNotification);
}

/// The real desktop notifier.
///
/// Windows and Linux use `notify-rust`. macOS uses a child `/usr/bin/osascript`
/// process because the `notify-rust` macOS backend runs AppleScript in-process.
pub struct DesktopNotifier;

impl Notifier for DesktopNotifier {
    fn notify(&self, notification: &TransitionNotification) {
        // A notification is best-effort: a desktop without a notification
        // service, a refusing script or a missing helper must never take the
        // GUI down. The tray tooltip keeps the current state visible either
        // way. The caller additionally catches a panic from this path.
        if let Err(error) = deliver(notification) {
            tracing::warn!(%error, "desktop notification could not be shown");
        }
    }
}

#[cfg(target_os = "macos")]
fn deliver(notification: &TransitionNotification) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let script = notification_script(notification.title(), &notification.body());
    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(&script)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cannot run /usr/bin/osascript: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.trim();
    Err(if detail.is_empty() {
        format!("osascript exited with {}", output.status)
    } else {
        format!("osascript exited with {}: {detail}", output.status)
    })
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

/// Quote one value as an AppleScript string literal.
///
/// The result is a single literal. Backslashes and double quotes are escaped,
/// and every control character (including newline, carriage return and tab) is
/// replaced by a space. Only the surrounding quotes and backslash escapes are
/// syntax; everything else is inert data, so a value such as `use default`
/// cannot be parsed as a command or an application name.
#[cfg(any(target_os = "macos", test))]
pub fn apple_script_literal(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            control if control.is_control() => quoted.push(' '),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// The exact AppleScript passed to `osascript`.
#[cfg(any(target_os = "macos", test))]
pub fn notification_script(title: &str, body: &str) -> String {
    format!(
        "display notification {} with title {}",
        apple_script_literal(body),
        apple_script_literal(title),
    )
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

#[cfg(test)]
mod tests {
    use super::{apple_script_literal, notification_script};

    /// Return the contents of every double-quoted literal, decoding the two
    /// escapes the builder emits. A raw quote or an unfinished literal would
    /// make this return a different number of values, which the tests assert.
    fn literals(script: &str) -> Vec<String> {
        let mut values = Vec::new();
        let mut characters = script.chars();
        while let Some(character) = characters.next() {
            if character != '"' {
                continue;
            }
            let mut value = String::new();
            loop {
                match characters.next() {
                    Some('\\') => match characters.next() {
                        Some('"') => value.push('"'),
                        Some('\\') => value.push('\\'),
                        Some(other) => {
                            value.push('\\');
                            value.push(other);
                        }
                        None => break,
                    },
                    Some('"') => break,
                    Some(other) => value.push(other),
                    None => break,
                }
            }
            values.push(value);
        }
        values
    }

    #[test]
    fn a_plain_notification_has_one_body_and_one_title_literal() {
        let script = notification_script("Aevan connected", "Tunnel is up at 10.0.0.1/32.");
        assert_eq!(
            script,
            concat!(
                "display notification \"Tunnel is up at 10.0.0.1/32.\"",
                " with title \"Aevan connected\"",
            )
        );
        assert_eq!(
            literals(&script),
            vec!["Tunnel is up at 10.0.0.1/32.", "Aevan connected"]
        );
    }

    #[test]
    fn quotes_backslashes_newlines_backticks_and_use_default_cannot_break_out() {
        let values = [
            "a \"quoted\" value",
            "a \\ backslash \\\" and a quote",
            "line one\nline two\r\nline three\tend",
            "`backticks` and $(shell) and ; semicolons",
            "use default",
            "use_default",
            "\"use default\"",
        ];

        for value in values {
            let script = notification_script(&format!("title {value}"), &format!("body {value}"));
            let parsed = literals(&script);
            assert_eq!(
                parsed.len(),
                2,
                "the script must contain exactly two literals: {script:?}"
            );

            let expected = value
                .chars()
                .map(|character| {
                    if character.is_control() {
                        ' '
                    } else {
                        character
                    }
                })
                .collect::<String>();
            assert_eq!(parsed[0], format!("body {expected}"));
            assert_eq!(parsed[1], format!("title {expected}"));

            // The whole script is one line with no control characters, and the
            // value is inert data inside a literal rather than a bare token.
            assert!(
                !script.chars().any(char::is_control),
                "control character survived: {script:?}"
            );
            assert!(script.starts_with("display notification \""));
            assert!(script.contains(" with title \""));
            assert!(
                script.matches('"').count() >= 4,
                "the title and body must each be quoted: {script:?}"
            );
        }
    }

    #[test]
    fn every_control_character_becomes_a_space() {
        let literal = apple_script_literal("a\u{0}b\u{1f}c\u{7f}d");
        assert_eq!(literal, "\"a b c d\"");
        assert!(!literal.chars().any(char::is_control));
    }

    #[test]
    fn a_double_quote_cannot_terminate_the_literal_early() {
        let script = notification_script("t", "\" with title \"evil");
        assert_eq!(
            literals(&script),
            vec!["\" with title \"evil".to_owned(), "t".to_owned()]
        );
        assert!(script.starts_with("display notification \"\\\" with title"));
    }
}
