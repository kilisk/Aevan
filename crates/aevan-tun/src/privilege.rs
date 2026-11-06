//! Best-effort elevation check for `aevan doctor`.
//!
//! This is diagnostic only. It never requests elevation and never changes the
//! process token. A false `Unknown` is preferable to guessing.

use std::process::Command;

/// Whether the current process appears privileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// Administrator (Windows) or uid 0 (Unix).
    Elevated,
    /// The check ran and the process is unprivileged.
    NotElevated,
    /// The check could not be performed.
    Unknown,
}

impl Elevation {
    /// Stable machine-readable spelling used by `aevan doctor --json`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Elevated => "elevated",
            Self::NotElevated => "not_elevated",
            Self::Unknown => "unknown",
        }
    }
}

/// Detect whether the process is elevated.
pub fn elevation() -> Elevation {
    imp::elevation()
}

#[cfg(target_os = "windows")]
mod imp {
    use super::{Command, Elevation};

    pub fn elevation() -> Elevation {
        let output = match Command::new("whoami").arg("/groups").output() {
            Ok(output) => output,
            Err(_) => return Elevation::Unknown,
        };
        if !output.status.success() {
            return Elevation::Unknown;
        }

        let groups = String::from_utf8_lossy(&output.stdout);
        // S-1-16-12288 = High mandatory level, S-1-16-16384 = System.
        if groups.contains("S-1-16-12288") || groups.contains("S-1-16-16384") {
            Elevation::Elevated
        } else {
            Elevation::NotElevated
        }
    }
}

#[cfg(unix)]
mod imp {
    use super::{Command, Elevation};

    pub fn elevation() -> Elevation {
        let output = match Command::new("id").arg("-u").output() {
            Ok(output) => output,
            Err(_) => return Elevation::Unknown,
        };
        if !output.status.success() {
            return Elevation::Unknown;
        }
        match String::from_utf8_lossy(&output.stdout).trim() {
            "0" => Elevation::Elevated,
            "" => Elevation::Unknown,
            _ => Elevation::NotElevated,
        }
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
mod imp {
    use super::Elevation;

    pub fn elevation() -> Elevation {
        Elevation::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::Elevation;

    #[test]
    fn machine_spellings_are_stable() {
        assert_eq!(Elevation::Elevated.as_str(), "elevated");
        assert_eq!(Elevation::NotElevated.as_str(), "not_elevated");
        assert_eq!(Elevation::Unknown.as_str(), "unknown");
    }
}
