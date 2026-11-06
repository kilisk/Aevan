//! Fallback applier for platforms without a real implementation.

use crate::command::CommandRunner;
use crate::error::TunError;
use crate::rollback::{Change, RollbackBackend};

/// Applier that refuses every change.
pub struct PlatformApplier;

impl PlatformApplier {
    /// Build the fallback applier. The runner is ignored.
    pub fn new(_runner: Box<dyn CommandRunner>, _interface: &str) -> Self {
        Self
    }

    /// Build the fallback applier, refusing because no implementation exists.
    pub fn open(_runner: Box<dyn CommandRunner>, _interface: &str) -> Result<Self, TunError> {
        check_prerequisites()?;
        Ok(Self)
    }
}

impl RollbackBackend for PlatformApplier {
    fn apply(&mut self, _change: &Change) -> Result<(), TunError> {
        Err(TunError::Unsupported(
            "no route/DNS/MTU applier for this platform",
        ))
    }
}

impl super::Applier for PlatformApplier {
    fn backend_name(&self) -> &'static str {
        "unsupported"
    }
}

/// No platform prerequisite is known.
pub fn check_prerequisites() -> Result<(), TunError> {
    Err(TunError::Unsupported(
        "no route/DNS/MTU applier for this platform",
    ))
}

/// No platform prerequisite is known; the observation does not change that.
pub fn check_prerequisites_observed(
    _observed: crate::privilege::Elevation,
) -> Result<(), TunError> {
    check_prerequisites()
}
