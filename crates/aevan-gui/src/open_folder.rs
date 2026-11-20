//! Open the platform file manager at the application log directory.
//!
//! The GUI owns this action; a failed launch becomes a banner, never a panic.
//! The command receives the configured log directory as a single argument.

use std::process::{Command, Stdio};

/// Open the log directory in Finder, Explorer or the desktop file manager.
pub fn open_log_folder() -> Result<(), String> {
    let dir = aevan_core::logging::log_dir()
        .ok_or_else(|| "the log directory is unavailable on this system".to_owned())?;
    aevan_core::logging::prepare_directory(&dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;

    #[cfg(target_os = "macos")]
    let mut command = Command::new("/usr/bin/open");
    #[cfg(windows)]
    let mut command = Command::new("explorer");
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = Command::new("xdg-open");
    #[cfg(not(any(unix, windows)))]
    let mut command = Command::new("xdg-open");

    command
        .arg(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("cannot open {}: {error}", dir.display()))
}
