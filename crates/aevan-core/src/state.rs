//! The connect state machine, as types only.
//!
//! One state machine is shared by the CLI, the
//! GUI and the daemon. This module defines the states; transitions and network
//! effects belong to `aevan-daemon`/`aevan-nc` in later milestones.

use std::fmt;

/// Lifecycle of one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum State {
    /// No tunnel is active.
    #[default]
    Disconnected,
    /// The transport is being established.
    Connecting,
    /// Credentials are being submitted (exactly one attempt).
    Authenticating,
    /// The gateway asked for a secondary factor such as a TOTP code.
    AwaitingToken,
    /// Authenticated; applying the NCP configuration and device settings.
    Configuring,
    /// The tunnel is up.
    Connected,
    /// Teardown is restoring routes, DNS and the device.
    Disconnecting,
    /// The last attempt failed; no tunnel is active.
    Failed,
}

impl State {
    /// Whether the state represents an active tunnel.
    pub fn is_connected(self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Whether the state represents a settled, non-transitional state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Disconnected | Self::Connected | Self::Failed)
    }

    /// Whether a connect request makes sense in this state.
    pub fn can_connect(self) -> bool {
        matches!(self, Self::Disconnected | Self::Failed)
    }

    /// Whether a disconnect request makes sense in this state.
    pub fn can_disconnect(self) -> bool {
        matches!(
            self,
            Self::Connecting
                | Self::Authenticating
                | Self::AwaitingToken
                | Self::Configuring
                | Self::Connected
        )
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Disconnected => "disconnected",
            Self::Connecting => "connecting",
            Self::Authenticating => "authenticating",
            Self::AwaitingToken => "awaiting-token",
            Self::Configuring => "configuring",
            Self::Connected => "connected",
            Self::Disconnecting => "disconnecting",
            Self::Failed => "failed",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disconnected() {
        assert_eq!(State::default(), State::Disconnected);
    }

    #[test]
    fn connected_is_the_only_active_state() {
        assert!(State::Connected.is_connected());
        for state in [
            State::Disconnected,
            State::Connecting,
            State::Authenticating,
            State::AwaitingToken,
            State::Configuring,
            State::Disconnecting,
            State::Failed,
        ] {
            assert!(!state.is_connected(), "{state} must not be connected");
        }
    }

    #[test]
    fn transition_guards() {
        assert!(State::Disconnected.can_connect());
        assert!(State::Failed.can_connect());
        assert!(!State::Connected.can_connect());
        assert!(State::Connected.can_disconnect());
        assert!(!State::Disconnected.can_disconnect());
    }
}
