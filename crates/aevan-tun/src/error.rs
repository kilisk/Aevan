//! Typed errors for the L3 layer.

/// Errors from a TUN backend or from configuration validation.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// The platform backend is not implemented yet (M2).
    #[error("TUN backend unsupported: {0}")]
    Unsupported(&'static str),
    /// The requested configuration is internally inconsistent.
    #[error("invalid TUN configuration: {0}")]
    InvalidConfig(String),
    /// The operation needs more privilege.
    #[error("TUN permission denied: {0}")]
    Permission(String),
    /// Operating-system I/O failure.
    #[error("TUN I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl TunError {
    /// Whether this error means the element a delete would remove is already
    /// absent.
    ///
    /// Windows `netsh` reports a missing route, address or interface on stderr
    /// (and sometimes stdout) with a message such as "The system cannot find
    /// the file specified" or "Element not found". Treating those as success is
    /// what makes rollback idempotent after a hard kill removed the adapter.
    pub fn is_already_absent(&self) -> bool {
        match self {
            Self::Io(error) => message_means_absent(&error.to_string()),
            _ => false,
        }
    }
}

/// Recognise platform messages that report an already-absent element.
///
/// Matching is case-insensitive and intentionally conservative: a message
/// must contain one of the documented "not found" phrases. Anything else stays
/// a real failure.
pub(crate) fn message_means_absent(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    const PHRASES: [&str; 9] = [
        "the system cannot find the file specified",
        "the system cannot find the path specified",
        "element not found",
        "not found",
        "no such",
        "does not exist",
        "cannot find",
        "there is no such",
        "not registered with the router",
    ];
    PHRASES.iter().any(|phrase| lower.contains(phrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_not_found_messages_are_already_absent() {
        for message in [
            "netsh exited with exit code: 1: The system cannot find the file specified.",
            "Element not found.",
            "The route was not found",
            "No such interface",
            "there is no such interface",
            "The specified interface does not exist.",
            "An interface with this name is not registered with the router.",
        ] {
            assert!(message_means_absent(message), "{message}");
        }
    }

    #[test]
    fn permission_and_other_io_errors_stay_failures() {
        for message in [
            "netsh exited with exit code: 5: Access is denied.",
            "The requested operation requires elevation.",
            "The service cannot be started.",
        ] {
            assert!(!message_means_absent(message), "{message}");
        }
        assert!(!TunError::Permission("denied".into()).is_already_absent());
        assert!(TunError::Io(std::io::Error::other("not found")).is_already_absent());
    }
}
