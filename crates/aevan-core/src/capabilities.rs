//! The project's cross-platform capabilities as data.
//!
//! Each capability names the modules that implement it on every platform. The
//! documentation generator (`scripts/platform-matrix.py`) reads this list, so
//! the capability inventory and the generated matrix cannot drift apart.
//!
//! An empty module list means the capability is deliberately absent on that
//! platform. A module that only returns `Unsupported` is a stub; a module with
//! a real implementation is implemented. That classification is code-level
//! only. Whether a capability was ever *run* on a platform is recorded
//! separately in `docs/platform-evidence.toml` and never inferred here.

/// One supported operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Microsoft Windows.
    Windows,
    /// Apple macOS.
    Macos,
    /// Linux.
    Linux,
}

/// A capability and the modules that implement it on each platform.
///
/// Paths are relative to the workspace root and are part of the data contract
/// with `scripts/platform-matrix.py`.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    /// Stable identifier used by the generator, evidence and gap files.
    pub id: &'static str,
    /// Human-facing title used in the generated matrix.
    pub title: &'static str,
    /// Implementing modules on Windows.
    pub windows: &'static [&'static str],
    /// Implementing modules on macOS.
    pub macos: &'static [&'static str],
    /// Implementing modules on Linux.
    pub linux: &'static [&'static str],
}

impl Capability {
    /// Return the module list for one platform.
    pub fn modules(&self, platform: Platform) -> &'static [&'static str] {
        match platform {
            Platform::Windows => self.windows,
            Platform::Macos => self.macos,
            Platform::Linux => self.linux,
        }
    }
}

/// Every capability the project claims to support somewhere.
pub const CAPABILITIES: &[Capability] = &[
    Capability {
        id: "tun-device",
        title: "TUN device",
        windows: &["crates/aevan-tun/src/platform/windows.rs"],
        macos: &["crates/aevan-tun/src/platform/macos.rs"],
        linux: &["crates/aevan-tun/src/platform/linux.rs"],
    },
    Capability {
        id: "address-and-routes",
        title: "Address and routes",
        windows: &["crates/aevan-tun/src/apply/windows.rs"],
        macos: &["crates/aevan-tun/src/apply/macos.rs"],
        linux: &["crates/aevan-tun/src/apply/linux.rs"],
    },
    Capability {
        id: "dns-apply",
        title: "DNS apply",
        windows: &["crates/aevan-tun/src/apply/windows.rs"],
        macos: &["crates/aevan-tun/src/apply/macos.rs"],
        linux: &["crates/aevan-tun/src/apply/linux.rs"],
    },
    Capability {
        id: "daemon-autostart",
        title: "Daemon autostart",
        windows: &["crates/aevan-daemon/src/autostart.rs"],
        macos: &["crates/aevan-daemon/src/autostart.rs"],
        linux: &["crates/aevan-daemon/src/autostart.rs"],
    },
    Capability {
        id: "tray-icon",
        title: "Tray icon",
        windows: &["crates/aevan-gui/src/tray.rs"],
        macos: &["crates/aevan-gui/src/tray.rs"],
        linux: &[],
    },
    Capability {
        id: "notifications",
        title: "Notifications",
        windows: &["crates/aevan-gui/src/notifications.rs"],
        macos: &["crates/aevan-gui/src/notifications.rs"],
        linux: &["crates/aevan-gui/src/notifications.rs"],
    },
    Capability {
        id: "single-instance",
        title: "Single instance",
        windows: &["crates/aevan-instance/src/lib.rs"],
        macos: &["crates/aevan-instance/src/lib.rs"],
        linux: &["crates/aevan-instance/src/lib.rs"],
    },
    Capability {
        id: "daemon-registration",
        title: "Daemon registration",
        windows: &["packaging/windows/aevan.wxs"],
        macos: &["crates/aevan-gui/src/macos_service.rs"],
        linux: &["packaging/linux/aevand.service"],
    },
    Capability {
        id: "installer-artifact",
        title: "Installer artifact",
        windows: &["packaging/windows/aevan.wxs"],
        macos: &["packaging/macos/build-pkg.sh"],
        linux: &["packaging/linux/aevand.spec", "packaging/linux/install.sh"],
    },
];

/// Look up one capability by its stable identifier.
pub fn find(id: &str) -> Option<&'static Capability> {
    CAPABILITIES.iter().find(|capability| capability.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_ids_are_unique_and_non_empty() {
        let mut seen = std::collections::BTreeSet::new();
        for capability in CAPABILITIES {
            assert!(!capability.id.is_empty());
            assert!(!capability.title.is_empty());
            assert!(seen.insert(capability.id), "duplicate id {}", capability.id);
        }
    }

    #[test]
    fn every_required_capability_is_present() {
        let required = [
            "tun-device",
            "address-and-routes",
            "dns-apply",
            "daemon-autostart",
            "tray-icon",
            "notifications",
            "single-instance",
            "daemon-registration",
            "installer-artifact",
        ];
        for id in required {
            assert!(find(id).is_some(), "missing capability {id}");
        }
    }

    #[test]
    fn platform_module_lists_use_workspace_relative_paths() {
        for capability in CAPABILITIES {
            for platform in [Platform::Windows, Platform::Macos, Platform::Linux] {
                for module in capability.modules(platform) {
                    assert!(
                        !module.starts_with('/') && !module.contains(".."),
                        "{}: {module}",
                        capability.id
                    );
                }
            }
        }
    }
}
