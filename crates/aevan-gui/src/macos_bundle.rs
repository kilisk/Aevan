//! Locate the daemon plist inside the running macOS app bundle.
//!
//! The daemon plist is not computed from a build-time or install-time path.
//! On macOS the bundle root is asked from `NSBundle.mainBundle.bundleURL`; the
//! fallback walks up from the running executable to the nearest ancestor that
//! contains `Contents/Info.plist`.
//!
//! A translocated bundle (quarantine) is its own outcome. Its plist really is
//! absent from the bundle path macOS reports, so reporting "the plist is
//! missing" there would be both wrong and unactionable.

use std::fmt;
use std::path::{Path, PathBuf};

/// Path of the bundle marker relative to the app bundle root.
pub const INFO_PLIST_RELATIVE_PATH: &str = "Contents/Info.plist";

/// Path segment macOS uses for a quarantined, translocated app.
pub const TRANSLOCATION_SEGMENT: &str = "/AppTranslocation/";

/// One specific reason the bundled daemon plist cannot be registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleProblem {
    /// macOS is running a quarantined, translocated copy of the app.
    Translocated { root: PathBuf },
}

impl BundleProblem {
    /// The path of the app bundle involved, when one was resolved.
    pub fn bundle_root(&self) -> Option<&Path> {
        match self {
            Self::Translocated { root } => Some(root),
        }
    }
}

impl fmt::Display for BundleProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Translocated { root } => formatter.write_str(&translocation_message(root)),
        }
    }
}

impl std::error::Error for BundleProblem {}

/// The guidance shown for a translocated bundle.
///
/// The command is always the documented `/Applications/Aevan.app` form so the
/// message can be copied verbatim, even when the translocated path differs.
pub fn translocation_message(bundle: &Path) -> String {
    format!(
        "macOS is running Aevan from a temporary location because the app is quarantined. Move Aevan.app to /Applications, remove the quarantine attribute, and relaunch:
xattr -dr com.apple.quarantine /Applications/Aevan.app
(resolved app bundle: {bundle})",
        bundle = bundle.display()
    )
}

/// Find the nearest ancestor of `executable` that is an app bundle root.
///
/// A fake tree is enough, so this is unit tested without a real macOS bundle.
/// The executable itself is checked first, which also accepts a directory that
/// directly contains `Contents/Info.plist`.
pub fn bundle_root_from(executable: &Path) -> Option<PathBuf> {
    executable
        .ancestors()
        .find(|ancestor| ancestor.join(INFO_PLIST_RELATIVE_PATH).is_file())
        .map(Path::to_path_buf)
}

/// Resolve the bundle root of the running program.
///
/// On macOS this asks the system first. A fallback walks up from the current
/// executable; a non-bundle directory returned by `NSBundle` is ignored so the
/// walk can still find the real root.
pub fn resolve_bundle_root() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    if let Some(root) = main_bundle_root() {
        return Some(root);
    }

    let executable = std::env::current_exe().ok()?;
    bundle_root_from(&executable)
}

/// Whether a resolved bundle path is a quarantine translocation.
pub fn is_translocated(root: &Path) -> bool {
    root.to_string_lossy()
        .replace('\\', "/")
        .contains(TRANSLOCATION_SEGMENT)
}

#[cfg(target_os = "macos")]
fn main_bundle_root() -> Option<PathBuf> {
    use objc2_foundation::NSBundle;

    let bundle = NSBundle::mainBundle();
    let url = bundle.bundleURL();
    let path = url.path()?;
    let root = PathBuf::from(path.to_string());
    if root.join(INFO_PLIST_RELATIVE_PATH).is_file() {
        Some(root)
    } else {
        None
    }
}
