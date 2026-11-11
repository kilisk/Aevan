//! Locate the daemon plist inside the running macOS app bundle.
//!
//! The daemon plist is not computed from a build-time or install-time path.
//! On macOS the bundle root is asked from `NSBundle.mainBundle.bundleURL`; the
//! fallback walks up from the running executable to the nearest ancestor that
//! contains `Contents/Info.plist`.

use std::path::{Path, PathBuf};

/// Path of the bundle marker relative to the app bundle root.
pub const INFO_PLIST_RELATIVE_PATH: &str = "Contents/Info.plist";

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
