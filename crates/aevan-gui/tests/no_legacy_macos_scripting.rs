//! Guard against reintroducing the macOS paths this build replaced.
//!
//! The needles are assembled from fragments so this test's own source does not
//! contain the literal names it forbids.
//!
//! The single exception is `aevan-gui/src/macos_elevate.rs`: an ad-hoc signed
//! build cannot register through `SMAppService`, so that module runs the native
//! administrator-prompt helper as a child and installs the legacy LaunchDaemon.
//! Remove that module and this exception once the app is
//! Developer ID signed, because `SMAppService` then works and no fallback is
//! needed.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    concat!("osa", "script"),
    concat!("Apple", "Script"),
    concat!("NSUser", "Notification"),
    concat!("SMJob", "Bless"),
    concat!("Authorization", "ExecuteWithPrivileges"),
    concat!("pb", "copy"),
];

/// The one module allowed to name the legacy scripting fallback.
const FALLBACK_MODULE: &str = "aevan-gui/src/macos_elevate.rs";

const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "toml", "md", "sh", "plist", "in", "rb", "desktop", "service", "spec", "wxs", "ps1",
    "yml", "yaml", "json", "txt",
];

fn collect(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read workspace directory") {
        let entry = entry.expect("read workspace entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type().expect("entry type").is_dir() {
            if name == "target" || name == ".git" {
                continue;
            }
            collect(&entry.path(), files);
        } else if is_text(&entry.path()) {
            files.push(entry.path());
        }
    }
}

fn is_text(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| TEXT_EXTENSIONS.contains(&extension))
}

#[test]
fn no_legacy_macos_scripting_names_remain_in_the_tree() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("crates")
        .canonicalize()
        .expect("resolve the crates directory");
    let mut files = Vec::new();
    collect(&root, &mut files);

    let scripting = concat!("osa", "script");
    let mut hits = Vec::new();
    let mut scripting_files = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).expect("read a UTF-8 text file");
        let relative = path
            .strip_prefix(&root)
            .expect("path under crates")
            .to_string_lossy()
            .replace('\\', "/");
        if text.contains(scripting) {
            scripting_files.push(relative.clone());
        }
        if relative == FALLBACK_MODULE {
            continue;
        }
        for needle in FORBIDDEN {
            if text.contains(needle) {
                hits.push(format!("{relative}: {needle}"));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "legacy macOS scripting names reappeared outside {FALLBACK_MODULE}:\n{}",
        hits.join("\n")
    );
    assert_eq!(
        scripting_files,
        vec![FALLBACK_MODULE.to_owned()],
        "the legacy scripting fallback must live only in {FALLBACK_MODULE}"
    );
}
