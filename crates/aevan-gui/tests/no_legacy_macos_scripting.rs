//! Guard against reintroducing the macOS paths this build replaced.
//!
//! The needles are assembled from fragments so this test's own source does not
//! contain the literal names it forbids.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    concat!("osa", "script"),
    concat!("Apple", "Script"),
    concat!("NSUser", "Notification"),
    concat!("SMJob", "Bless"),
    concat!("Authorization", "ExecuteWithPrivileges"),
];

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

    let mut hits = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).expect("read a UTF-8 text file");
        for needle in FORBIDDEN {
            if text.contains(needle) {
                hits.push(format!("{}: {needle}", path.display()));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "legacy macOS scripting names reappeared:\n{}",
        hits.join("\n")
    );
}
