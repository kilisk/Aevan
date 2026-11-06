//! Helpers that keep credentials out of logs and diagnostics.
//!
//! Values can leak in surprising places, so redaction is a library primitive,
//! not a convention. Two complementary tools are provided:
//!
//! * [`redact_value`] / [`redact_header`] redact a value based on its key.
//! * [`Redactor`] removes known secret values from arbitrary text.

use std::borrow::Cow;

use zeroize::Zeroizing;

/// Replacement text written wherever a secret was removed.
pub const REDACTED: &str = "[REDACTED]";

/// Case-insensitive key fragments that always denote a secret.
///
/// Over-redaction is intentional: a false positive only hides a diagnostic,
/// while a false negative can leak a credential.
pub const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "token",
    "cookie",
    "authorization",
    "secret",
    "credential",
];

/// Whether a key (header name, TOML key, JSON field, ...) names a secret.
///
/// The match is case-insensitive and treats fragment matches such as
/// `Set-Cookie`, `password#2` and `Proxy-Authorization` as sensitive.
pub fn is_sensitive_key(key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| key.contains(fragment))
}

/// Redact `value` when `key` is sensitive.
///
/// Returns a borrowed value for non-sensitive keys so callers can keep the
/// fast path allocation-free.
pub fn redact_value<'a>(key: &str, value: &'a str) -> Cow<'a, str> {
    if is_sensitive_key(key) {
        Cow::Borrowed(REDACTED)
    } else {
        Cow::Borrowed(value)
    }
}

/// Render a `key=value` pair for diagnostics, redacting sensitive keys.
pub fn redact_key_value(key: &str, value: &str) -> String {
    format!("{key}={}", redact_value(key, value))
}

/// Redact the value side of a `Name: value` header line.
///
/// Lines without a colon, or with a non-sensitive name, are returned
/// unchanged. The name is preserved because it is useful and not secret.
pub fn redact_header(line: &str) -> String {
    match line.split_once(':') {
        Some((name, _)) if is_sensitive_key(name) => {
            format!("{}: {REDACTED}", name.trim())
        }
        _ => line.to_owned(),
    }
}

/// Removes registered secret values from arbitrary text (log lines, errors,
/// JSON fragments).
///
/// Secrets are kept in a [`Zeroizing`] buffer so they are wiped when the
/// redactor is dropped. The type deliberately implements neither `Debug` nor
/// `Display`, so a redactor cannot be accidentally logged.
pub struct Redactor {
    secrets: Zeroizing<Vec<String>>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// An empty redactor.
    pub fn new() -> Self {
        Self {
            secrets: Zeroizing::new(Vec::new()),
        }
    }

    /// Build a redactor from known secret values.
    pub fn with_secrets<I, S>(secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut redactor = Self::new();
        for secret in secrets {
            redactor.add_secret(secret);
        }
        redactor
    }

    /// Register one secret value. Empty values are ignored.
    pub fn add_secret(&mut self, secret: impl Into<String>) {
        let secret = secret.into();
        if !secret.is_empty() {
            self.secrets.push(secret);
        }
    }

    /// Remove every registered secret value from `text`.
    ///
    /// Longer secrets are replaced first so a secret that contains another
    /// registered value cannot leave a partial fragment behind.
    pub fn redact(&self, text: &str) -> String {
        let mut secrets: Vec<&str> = self
            .secrets
            .iter()
            .map(String::as_str)
            .filter(|secret| !secret.is_empty())
            .collect();
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));

        let mut out = text.to_owned();
        for secret in secrets {
            out = out.replace(secret, REDACTED);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_required_key_is_sensitive() {
        for key in ["password", "token", "cookie", "authorization"] {
            assert!(is_sensitive_key(key), "{key} must be sensitive");
            assert_eq!(redact_value(key, "hunter2"), REDACTED);
        }
    }

    #[test]
    fn sensitivity_is_case_insensitive_and_fragment_based() {
        for key in [
            "PASSWORD",
            "Password",
            "password#2",
            "TOTP-Token",
            "Set-Cookie",
            "Proxy-Authorization",
            "client_secret",
            "Credentials",
        ] {
            assert!(is_sensitive_key(key), "{key} must be sensitive");
        }
    }

    #[test]
    fn ordinary_keys_are_not_redacted() {
        for key in ["username", "realm", "url", "user-agent", "content-type"] {
            assert!(!is_sensitive_key(key), "{key} must not be sensitive");
            assert_eq!(redact_value(key, "visible"), "visible");
        }
    }

    #[test]
    fn header_redaction_keeps_the_name() {
        assert_eq!(
            redact_header("Authorization: Bearer abc"),
            "Authorization: [REDACTED]"
        );
        assert_eq!(
            redact_header("set-cookie: session=1"),
            "set-cookie: [REDACTED]"
        );
        assert_eq!(
            redact_header("Content-Type: text/html"),
            "Content-Type: text/html"
        );
        assert_eq!(redact_header("not-a-header"), "not-a-header");
    }

    #[test]
    fn key_value_rendering_redacts_only_secrets() {
        assert_eq!(
            redact_key_value("password", "hunter2"),
            "password=[REDACTED]"
        );
        assert_eq!(
            redact_key_value("realm", "example_realm"),
            "realm=example_realm"
        );
    }

    #[test]
    fn redactor_removes_known_values() {
        let redactor = Redactor::with_secrets(["hunter2", "123456789"]);
        let text = "login password=hunter2 token=123456789 realm=example_realm";
        let redacted = redactor.redact(text);
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("123456789"));
        assert!(redacted.contains("example_realm"));
        assert_eq!(redacted.matches(REDACTED).count(), 2);
    }

    #[test]
    fn redactor_prefers_longer_secrets() {
        let redactor = Redactor::with_secrets(["abcd", "abcdef"]);
        assert_eq!(redactor.redact("abcdef"), REDACTED);
    }

    #[test]
    fn empty_secrets_are_ignored() {
        let mut redactor = Redactor::new();
        redactor.add_secret("");
        assert_eq!(redactor.redact("nothing to hide"), "nothing to hide");
    }
}
