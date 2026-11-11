//! Locate and validate the daemon plist inside the running macOS app bundle.
//!
//! The daemon plist is not computed from a build-time or install-time path.
//! On macOS the bundle root is asked from `NSBundle.mainBundle.bundleURL`; the
//! fallback walks up from the running executable to the nearest ancestor that
//! contains `Contents/Info.plist`. Verification then checks each expected
//! artifact in order so a failure names the step and the exact path.
//!
//! A translocated bundle (quarantine) is its own outcome. Its plist really is
//! absent from the bundle path macOS reports, so reporting "the plist is
//! missing" there would be both wrong and unactionable.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use aevan_daemon::launchd;

/// File name of the bundled LaunchDaemon plist.
pub const PLIST_NAME: &str = launchd::PLIST_NAME;

/// Path of the daemon plist relative to the app bundle root.
pub const PLIST_RELATIVE_PATH: &str =
    "Contents/Library/LaunchDaemons/com.github.kilisk.aevand.plist";

/// Path of the bundle marker relative to the app bundle root.
pub const INFO_PLIST_RELATIVE_PATH: &str = "Contents/Info.plist";

/// Path segment macOS uses for a quarantined, translocated app.
pub const TRANSLOCATION_SEGMENT: &str = "/AppTranslocation/";

/// Directory that holds the bundled LaunchDaemon plist, relative to the root.
pub const LAUNCH_DAEMONS_RELATIVE_PATH: &str = "Contents/Library/LaunchDaemons";

/// A bundle root and the daemon plist that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleInfo {
    /// The app bundle root that was resolved and verified.
    pub root: PathBuf,
    /// The verified daemon plist inside that root.
    pub plist: PathBuf,
}

/// One specific reason the bundled daemon plist cannot be registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleProblem {
    /// No app bundle could be resolved from the running program.
    NotInBundle,
    /// macOS is running a quarantined, translocated copy of the app.
    Translocated { root: PathBuf },
    /// The resolved bundle root does not exist.
    MissingRoot { root: PathBuf },
    /// The bundle has no `Contents/Library/LaunchDaemons` directory.
    MissingLaunchDaemons { root: PathBuf, path: PathBuf },
    /// The checked plist path does not exist inside the bundle.
    MissingPlist { root: PathBuf, path: PathBuf },
    /// The plist exists but cannot be read.
    UnreadablePlist {
        root: PathBuf,
        path: PathBuf,
        reason: String,
    },
    /// The plist's `Label` is not the daemon's label.
    LabelMismatch {
        root: PathBuf,
        path: PathBuf,
        label: Option<String>,
    },
}

impl BundleProblem {
    /// The path of the app bundle involved, when one was resolved.
    pub fn bundle_root(&self) -> Option<&Path> {
        match self {
            Self::NotInBundle => None,
            Self::Translocated { root }
            | Self::MissingRoot { root }
            | Self::MissingLaunchDaemons { root, .. }
            | Self::MissingPlist { root, .. }
            | Self::UnreadablePlist { root, .. }
            | Self::LabelMismatch { root, .. } => Some(root),
        }
    }
}

impl fmt::Display for BundleProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInBundle => formatter.write_str(
                "The Aevan app bundle could not be located from the running program, \
so the daemon plist cannot be checked. Reinstall Aevan and try again.",
            ),
            Self::Translocated { root } => formatter.write_str(&translocation_message(root)),
            Self::MissingRoot { root } => write!(
                formatter,
                "The app bundle root {path} does not exist, so the Aevan daemon plist cannot be found. Reinstall Aevan and try again.",
                path = root.display()
            ),
            Self::MissingLaunchDaemons { root, path } => write!(
                formatter,
                "The app bundle at {root} has no LaunchDaemons directory: expected {path}. Reinstall Aevan and try again.",
                root = root.display(),
                path = path.display()
            ),
            Self::MissingPlist { root, path } => write!(
                formatter,
                "The Aevan daemon plist is missing from the app bundle: expected {path} inside the app bundle at {root}. Reinstall Aevan and try again.",
                path = path.display(),
                root = root.display()
            ),
            Self::UnreadablePlist { root, path, reason } => write!(
                formatter,
                "The Aevan daemon plist at {path} inside the app bundle at {root} is not readable ({reason}). Reinstall Aevan and try again.",
                path = path.display(),
                root = root.display()
            ),
            Self::LabelMismatch { root, path, label } => match label {
                Some(label) => write!(
                    formatter,
                    "The Aevan daemon plist at {path} inside the app bundle at {root} has Label '{label}', expected '{expected}'. Reinstall Aevan and try again.",
                    path = path.display(),
                    root = root.display(),
                    expected = launchd::LABEL
                ),
                None => write!(
                    formatter,
                    "The Aevan daemon plist at {path} inside the app bundle at {root} has no Label, expected '{expected}'. Reinstall Aevan and try again.",
                    path = path.display(),
                    root = root.display(),
                    expected = launchd::LABEL
                ),
            },
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
        "macOS is running Aevan from a temporary location because the app is quarantined. \
Move Aevan.app to /Applications, remove the quarantine attribute, and relaunch:\n\
xattr -dr com.apple.quarantine /Applications/Aevan.app\n\
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

/// Whether a resolved bundle path is a quarantine translocation.
pub fn is_translocated(root: &Path) -> bool {
    root.to_string_lossy()
        .replace('\\', "/")
        .contains(TRANSLOCATION_SEGMENT)
}

/// Check a resolved bundle root in order and return the verified plist.
///
/// The order is: the root exists, the LaunchDaemons directory exists, the
/// plist exists and is readable, and the plist `Label` is the daemon's label.
pub fn verify(root: &Path) -> Result<BundleInfo, BundleProblem> {
    if is_translocated(root) {
        return Err(BundleProblem::Translocated {
            root: root.to_path_buf(),
        });
    }
    if !root.is_dir() {
        return Err(BundleProblem::MissingRoot {
            root: root.to_path_buf(),
        });
    }

    let launch_daemons = root.join(LAUNCH_DAEMONS_RELATIVE_PATH);
    if !launch_daemons.is_dir() {
        return Err(BundleProblem::MissingLaunchDaemons {
            root: root.to_path_buf(),
            path: launch_daemons,
        });
    }

    let plist = root.join(PLIST_RELATIVE_PATH);
    if !plist.is_file() {
        return Err(BundleProblem::MissingPlist {
            root: root.to_path_buf(),
            path: plist,
        });
    }
    let contents = fs::read_to_string(&plist).map_err(|error| BundleProblem::UnreadablePlist {
        root: root.to_path_buf(),
        path: plist.clone(),
        reason: error.to_string(),
    })?;

    let label = plist_label(&contents);
    if label.as_deref() != Some(launchd::LABEL) {
        return Err(BundleProblem::LabelMismatch {
            root: root.to_path_buf(),
            path: plist,
            label,
        });
    }

    Ok(BundleInfo {
        root: root.to_path_buf(),
        plist,
    })
}

/// Resolve the running app bundle and verify it before any registration.
pub fn verify_resolved() -> Result<BundleInfo, BundleProblem> {
    match resolve_bundle_root() {
        Some(root) => verify(&root),
        None => Err(BundleProblem::NotInBundle),
    }
}

/// The message used when ServiceManagement itself cannot find the plist.
///
/// The pre-registration check normally makes this unreachable, but a race or a
/// signed-build registration error must still name the checked paths.
pub fn service_management_not_found_message() -> String {
    match resolve_bundle_root() {
        Some(root) => format!(
            "ServiceManagement could not find the bundled daemon plist: expected {path} inside the app bundle at {root}.",
            path = root.join(PLIST_RELATIVE_PATH).display(),
            root = root.display()
        ),
        None => BundleProblem::NotInBundle.to_string(),
    }
}

/// Read the first `<key>Label</key>` value from plist XML text.
fn plist_label(contents: &str) -> Option<String> {
    let key = "<key>Label</key>";
    let after_key = &contents[contents.find(key)? + key.len()..];
    let after_open = &after_key[after_key.find("<string>")? + "<string>".len()..];
    let end = after_open.find("</string>")?;
    Some(after_open[..end].trim().to_owned())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::relaunch::{RegisterMethod, RelaunchOps, ServiceState, StartMethod};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let unique = NEXT.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "aevan-bundle-{label}-{}-{nanos}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        fs::write(path, contents).expect("write fixture");
    }

    fn plist(label: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n<key>Label</key>\n<string>{label}</string>\n</dict>\n</plist>\n"
        )
    }

    fn fake_bundle(temp: &TempDir, label: &str) -> PathBuf {
        let root = temp.path().join("Aevan.app");
        write(&root.join(INFO_PLIST_RELATIVE_PATH), "<plist/>");
        write(&root.join(PLIST_RELATIVE_PATH), &plist(label));
        root
    }

    #[test]
    fn the_bundle_root_is_found_from_a_nested_executable() {
        let temp = TempDir::new("nested");
        let root = fake_bundle(&temp, launchd::LABEL);
        let executable = root.join("Contents/MacOS/Helpers/aevan-gui");

        assert_eq!(bundle_root_from(&executable), Some(root));
    }

    #[test]
    fn there_is_no_bundle_root_without_contents_info_plist() {
        let temp = TempDir::new("no-bundle");
        let executable = temp.path().join("target/debug/aevan-gui");

        assert_eq!(bundle_root_from(&executable), None);
    }

    #[test]
    fn translocation_is_its_own_outcome_with_the_quarantine_command() {
        let root =
            PathBuf::from("/private/var/folders/ab/cdef/T/AppTranslocation/1234-5678/d/Aevan.app");
        let problem = verify(&root).expect_err("translocated bundles are refused");

        let message = problem.to_string();
        assert!(matches!(problem, BundleProblem::Translocated { .. }));
        assert!(message.contains("temporary location"), "{message}");
        assert!(message.contains("quarantined"), "{message}");
        assert!(
            message.contains("xattr -dr com.apple.quarantine /Applications/Aevan.app"),
            "{message}"
        );
        assert!(!message.contains("plist is missing"), "{message}");
    }

    #[test]
    fn a_missing_plist_names_the_checked_path_and_bundle_root() {
        let temp = TempDir::new("missing-plist");
        let root = temp.path().join("Aevan.app");
        write(&root.join(INFO_PLIST_RELATIVE_PATH), "<plist/>");
        fs::create_dir_all(root.join(LAUNCH_DAEMONS_RELATIVE_PATH)).expect("launchdaemons");
        let checked = root.join(PLIST_RELATIVE_PATH);

        let problem = verify(&root).expect_err("the plist is absent");
        let message = problem.to_string();
        assert!(matches!(problem, BundleProblem::MissingPlist { .. }));
        assert!(message.contains("expected"), "{message}");
        assert!(
            message.contains(&checked.display().to_string()),
            "{message}"
        );
        assert!(message.contains(&root.display().to_string()), "{message}");
    }

    #[test]
    fn a_missing_launchdaemons_directory_is_its_own_failure() {
        let temp = TempDir::new("missing-launchdaemons");
        let root = temp.path().join("Aevan.app");
        write(&root.join(INFO_PLIST_RELATIVE_PATH), "<plist/>");

        let problem = verify(&root).expect_err("no LaunchDaemons directory");
        assert!(matches!(
            problem,
            BundleProblem::MissingLaunchDaemons { .. }
        ));
        let message = problem.to_string();
        assert!(
            message.contains(
                &root
                    .join(LAUNCH_DAEMONS_RELATIVE_PATH)
                    .display()
                    .to_string()
            ),
            "{message}"
        );
    }

    #[test]
    fn a_label_mismatch_is_reported_separately() {
        let temp = TempDir::new("label");
        let root = fake_bundle(&temp, "com.example.other");

        let problem = verify(&root).expect_err("the label does not match");
        assert!(matches!(problem, BundleProblem::LabelMismatch { .. }));
        let message = problem.to_string();
        assert!(message.contains("com.example.other"), "{message}");
        assert!(message.contains(launchd::LABEL), "{message}");
        assert!(message.contains("Label"), "{message}");
        assert!(!message.contains("missing"), "{message}");
    }

    #[test]
    fn a_valid_bundle_passes_every_check_and_reaches_registration() {
        let temp = TempDir::new("valid");
        let root = fake_bundle(&temp, launchd::LABEL);

        let bundle = verify(&root).expect("a complete bundle is accepted");
        assert_eq!(bundle.root, root);
        assert_eq!(bundle.plist, root.join(PLIST_RELATIVE_PATH));

        let ops = FakeOps::default();
        let report = crate::relaunch::relaunch(&ops).expect("registration is reached");
        assert_eq!(report.method, StartMethod::Registered);
        assert_eq!(ops.registers.get(), 1);
    }

    #[derive(Default)]
    struct FakeOps {
        statuses: Cell<usize>,
        registers: Cell<usize>,
    }

    impl RelaunchOps for FakeOps {
        fn socket_answers(&self) -> bool {
            false
        }

        fn service_status(&self) -> Result<ServiceState, String> {
            let call = self.statuses.get();
            self.statuses.set(call + 1);
            Ok(if call == 0 {
                ServiceState::NotRegistered
            } else {
                ServiceState::Enabled
            })
        }

        fn register(&self) -> Result<RegisterMethod, String> {
            self.registers.set(self.registers.get() + 1);
            Ok(RegisterMethod::ServiceManagement)
        }

        fn kickstart(&self) -> Result<(), String> {
            Ok(())
        }

        fn wait_ready(&self) -> Result<(), String> {
            Ok(())
        }
    }
}
