//! Error taxonomy and the process exit codes.

use std::fmt;

/// Public process exit codes. These are part of the CLI contract.
pub mod exit_code {
    /// Success.
    pub const OK: i32 = 0;
    /// Internal/unspecified failure. Not part of the documented contract; used
    /// for unimplemented M0 commands and local I/O errors.
    pub const FAILURE: i32 = 1;
    /// The command needs interaction (token, role, confirmation).
    pub const INTERACTION: i32 = 2;
    /// Authentication was rejected by the gateway.
    pub const AUTH_REJECTED: i32 = 3;
    /// Network, DNS or TLS failure.
    pub const NETWORK: i32 = 4;
    /// Already connected or already disconnected.
    pub const ALREADY_IN_STATE: i32 = 5;
    /// Insufficient privilege (elevation required).
    pub const PRIVILEGE: i32 = 6;
    /// The gateway or its configuration is not supported.
    pub const UNSUPPORTED: i32 = 7;
}

/// Errors surfaced by `aevan` commands.
///
/// Every variant maps to a stable process exit code through
/// [`AevanError::exit_code`]. Error messages never include credentials; callers
/// must keep secrets out of the payload strings.
#[derive(Debug, thiserror::Error)]
pub enum AevanError {
    /// The command needs user interaction (for example a one-time token).
    #[error("interaction required: {0}")]
    Interaction(String),
    /// The gateway rejected the credentials.
    #[error("authentication rejected: {0}")]
    AuthRejected(String),
    /// Network, DNS or TLS failure.
    #[error("network or TLS failure: {0}")]
    Network(String),
    /// The requested state already holds.
    #[error("already in requested state: {0}")]
    AlreadyInState(String),
    /// The operation needs more privilege than the process has.
    #[error("insufficient privilege: {0}")]
    Privilege(String),
    /// The gateway or configuration is outside the supported set.
    #[error("unsupported gateway or configuration: {0}")]
    Unsupported(String),
    /// Profile, TOML or permission problem.
    #[error("configuration error: {0}")]
    Config(String),
    /// Local I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The command is part of the CLI surface but lands in a later milestone.
    #[error("command not implemented at M0: {0}")]
    Unimplemented(&'static str),
}

impl AevanError {
    /// Rebuild an error from a documented exit code and a message.
    ///
    /// The daemon reports its failures as `exit_code` values, so the CLI uses
    /// this to preserve the contract instead of flattening every remote error
    /// into the generic internal code. Unknown codes map to
    /// [`std::io::Error`] (exit 1), which is reserved for genuinely internal
    /// failures.
    pub fn from_exit_code(code: i32, message: impl Into<String>) -> Self {
        let message = message.into();
        match code {
            exit_code::INTERACTION => Self::Interaction(message),
            exit_code::AUTH_REJECTED => Self::AuthRejected(message),
            exit_code::NETWORK => Self::Network(message),
            exit_code::ALREADY_IN_STATE => Self::AlreadyInState(message),
            exit_code::PRIVILEGE => Self::Privilege(message),
            exit_code::UNSUPPORTED => Self::Unsupported(message),
            _ => Self::Io(std::io::Error::other(message)),
        }
    }

    /// Map the error to the documented process exit code.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Interaction(_) => exit_code::INTERACTION,
            Self::AuthRejected(_) => exit_code::AUTH_REJECTED,
            Self::Network(_) => exit_code::NETWORK,
            Self::AlreadyInState(_) => exit_code::ALREADY_IN_STATE,
            Self::Privilege(_) => exit_code::PRIVILEGE,
            Self::Unsupported(_) => exit_code::UNSUPPORTED,
            Self::Config(_) | Self::Io(_) | Self::Unimplemented(_) => exit_code::FAILURE,
        }
    }
}

/// Convenience alias used by the CLI and daemon.
pub type AevanResult<T> = Result<T, AevanError>;

impl From<toml::de::Error> for AevanError {
    fn from(error: toml::de::Error) -> Self {
        Self::Config(format!("invalid TOML: {error}"))
    }
}

impl From<toml::ser::Error> for AevanError {
    fn from(error: toml::ser::Error) -> Self {
        Self::Config(format!("could not serialise TOML: {error}"))
    }
}

/// A small newtype for an exit code that can be handed to `std::process`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus(pub i32);

impl From<AevanError> for ExitStatus {
    fn from(error: AevanError) -> Self {
        Self(error.exit_code())
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_exit_codes_are_stable() {
        assert_eq!(exit_code::OK, 0);
        assert_eq!(exit_code::INTERACTION, 2);
        assert_eq!(exit_code::AUTH_REJECTED, 3);
        assert_eq!(exit_code::NETWORK, 4);
        assert_eq!(exit_code::ALREADY_IN_STATE, 5);
        assert_eq!(exit_code::PRIVILEGE, 6);
        assert_eq!(exit_code::UNSUPPORTED, 7);
    }

    #[test]
    fn errors_map_to_their_exit_codes() {
        assert_eq!(AevanError::Interaction("token".into()).exit_code(), 2);
        assert_eq!(AevanError::AuthRejected("denied".into()).exit_code(), 3);
        assert_eq!(AevanError::Network("tls".into()).exit_code(), 4);
        assert_eq!(
            AevanError::AlreadyInState("connected".into()).exit_code(),
            5
        );
        assert_eq!(AevanError::Privilege("root".into()).exit_code(), 6);
        assert_eq!(AevanError::Unsupported("ift".into()).exit_code(), 7);
    }

    #[test]
    fn exit_codes_round_trip_through_from_exit_code() {
        for code in [2, 3, 4, 5, 6, 7] {
            let error = AevanError::from_exit_code(code, "relayed");
            assert_eq!(error.exit_code(), code, "{error}");
        }
        let internal = AevanError::from_exit_code(1, "daemon protocol violation");
        assert_eq!(internal.exit_code(), exit_code::FAILURE);
    }
}
