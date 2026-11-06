#![deny(unsafe_code)]
//! IF-T/TLS (Pulse) transport — optional research track, **M6**.
//!
//! This crate is a stub behind the non-default `ift` feature. The live gateway
//! rejects a non-vendor IFT handshake before
//! any credential is sent, so NC is the only critical-path transport.
//!
//! Enable with `cargo build -p aevan-ift --features ift` when M6 starts.

use aevan_core::{AevanError, AevanResult};

/// Milestone that will implement this transport.
pub const MILESTONE: &str = "M6";

/// Whether the optional transport was compiled in.
pub fn enabled() -> bool {
    cfg!(feature = "ift")
}

/// The optional transport surface, compiled only with `--features ift`.
#[cfg(feature = "ift")]
pub mod transport {
    use super::{AevanError, AevanResult};

    /// Connect over IF-T/TLS. The implementation is M6.
    pub fn connect() -> AevanResult<()> {
        Err(AevanError::Unimplemented("aevan-ift transport (M6)"))
    }
}

/// Without the feature the surface still exists, but is explicitly disabled.
#[cfg(not(feature = "ift"))]
pub mod transport {
    use super::{AevanError, AevanResult};

    /// Connect over IF-T/TLS. Disabled unless `--features ift` is used.
    pub fn connect() -> AevanResult<()> {
        Err(AevanError::Unimplemented(
            "aevan-ift is disabled; rebuild with --features ift (M6)",
        ))
    }
}

/// Compile-time check that the feature gate keeps the default build lean.
#[cfg(feature = "ift")]
pub const FEATURE_BUILD: bool = true;

/// Compile-time check that the feature gate keeps the default build lean.
#[cfg(not(feature = "ift"))]
pub const FEATURE_BUILD: bool = false;

#[cfg(all(test, not(feature = "ift")))]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default() {
        assert!(!enabled());
        assert!(transport::connect().is_err());
    }
}

#[cfg(all(test, feature = "ift"))]
mod feature_tests {
    use super::*;

    #[test]
    fn feature_build_is_still_a_stub() {
        assert!(enabled());
        assert!(transport::connect().is_err());
    }
}
