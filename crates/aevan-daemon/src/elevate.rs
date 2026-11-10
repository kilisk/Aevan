//! Start the sibling daemon with one UAC prompt and launch the GUI detached.
//!
//! On Windows the only way to create the Wintun adapter without a manual
//! elevated terminal is to ask the shell to start `aevand.exe` with the
//! `runas` verb. The Win32 call is confined to [`imp`] and kept free of any
//! credential handling: the daemon is only a listener until a control request
//! arrives.
//!
//! macOS has no elevated shell path in the CLI. The GUI registers the bundled
//! LaunchDaemon with ServiceManagement (and, for an ad-hoc signed build, falls
//! back to one administrator prompt there), so the CLI only points the user at
//! the app instead of starting a root process itself.
//!
//! Tests never call this module. The launcher's decision logic lives behind a
//! trait in `aevan-cli`, so no process is spawned in the test suite.

use std::path::Path;

/// Result of asking the operating system to start a process elevated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOutcome {
    /// The elevated process was accepted by the shell.
    Started,
    /// The user dismissed the UAC prompt.
    Cancelled,
    /// The shell refused for another reason.
    Failed(String),
}

/// Start `executable` with `args` elevated.
///
/// Windows shows the single UAC prompt. Other platforms report that this is
/// unsupported; the CLI prints the normal guidance to start `aevand` manually.
pub fn start_elevated(executable: &Path, args: &[&str]) -> StartOutcome {
    imp::start_elevated(executable, args)
}

/// Start `executable` without a console and without waiting for it.
pub fn spawn_detached(executable: &Path) -> std::io::Result<()> {
    imp::spawn_detached(executable)
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::ptr;

    use super::StartOutcome;

    const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
    const SW_HIDE: i32 = 0;
    const ERROR_CANCELLED: u32 = 1223;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    #[repr(C)]
    struct ShellExecuteInfoW {
        cb_size: u32,
        f_mask: u32,
        hwnd: *mut c_void,
        lp_verb: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show: i32,
        h_inst_app: *mut c_void,
        lp_id_list: *mut c_void,
        lp_class: *const u16,
        hkey_class: *mut c_void,
        dw_hot_key: u32,
        h_icon_or_monitor: *mut c_void,
        h_process: *mut c_void,
    }

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteExW(info: *mut ShellExecuteInfoW) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn quote(argument: &str) -> String {
        if argument.is_empty() {
            "\"\"".to_owned()
        } else if argument.contains([' ', '\t', '"']) {
            format!("\"{}\"", argument.replace('"', "\\\""))
        } else {
            argument.to_owned()
        }
    }

    pub fn start_elevated(executable: &Path, args: &[&str]) -> StartOutcome {
        let verb = wide(OsStr::new("runas"));
        let file = wide(executable.as_os_str());
        let parameters: Option<Vec<u16>> = if args.is_empty() {
            None
        } else {
            let line = args
                .iter()
                .map(|argument| quote(argument))
                .collect::<Vec<_>>()
                .join(" ");
            Some(wide(OsStr::new(&line)))
        };
        let directory = executable.parent().map(|parent| wide(parent.as_os_str()));

        let mut info = ShellExecuteInfoW {
            cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
            f_mask: SEE_MASK_NOCLOSEPROCESS,
            hwnd: ptr::null_mut(),
            lp_verb: verb.as_ptr(),
            lp_file: file.as_ptr(),
            lp_parameters: parameters
                .as_ref()
                .map_or(ptr::null(), |line| line.as_ptr()),
            lp_directory: directory.as_ref().map_or(ptr::null(), |path| path.as_ptr()),
            n_show: SW_HIDE,
            h_inst_app: ptr::null_mut(),
            lp_id_list: ptr::null_mut(),
            lp_class: ptr::null(),
            hkey_class: ptr::null_mut(),
            dw_hot_key: 0,
            h_icon_or_monitor: ptr::null_mut(),
            h_process: ptr::null_mut(),
        };

        // SAFETY: `info` is a fully initialized SHELLEXECUTEINFOW with the
        // documented `cbSize`; every pointer either points at a live local or
        // is null, and the shell only reads them for the duration of the call.
        // The returned process handle belongs to this process and is closed
        // below.
        let started = unsafe { ShellExecuteExW(&mut info) };
        if started == 0 {
            // SAFETY: GetLastError reads the calling thread's last-error value
            // and has no preconditions.
            let code = unsafe { GetLastError() };
            if code == ERROR_CANCELLED {
                return StartOutcome::Cancelled;
            }
            return StartOutcome::Failed(format!(
                "Windows could not start {} with Administrator (error {code})",
                executable.display()
            ));
        }
        if !info.h_process.is_null() {
            // SAFETY: the handle was returned by ShellExecuteExW above and is
            // not used again.
            unsafe {
                CloseHandle(info.h_process);
            }
        }
        StartOutcome::Started
    }

    pub fn spawn_detached(executable: &Path) -> std::io::Result<()> {
        std::process::Command::new(executable)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .map(|_child| ())
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::Path;

    use super::StartOutcome;

    pub fn start_elevated(executable: &Path, _args: &[&str]) -> StartOutcome {
        StartOutcome::Failed(format!(
            "starting {} with administrator privileges is not part of the macOS CLI; launch Aevan once so it can register or install the bundled LaunchDaemon",
            executable.display()
        ))
    }

    pub fn spawn_detached(executable: &Path) -> std::io::Result<()> {
        std::process::Command::new(executable)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_child| ())
    }
}

#[cfg(all(not(windows), not(target_os = "macos")))]
mod imp {
    use std::path::Path;

    use super::StartOutcome;

    pub fn start_elevated(executable: &Path, _args: &[&str]) -> StartOutcome {
        StartOutcome::Failed(format!(
            "starting {} with Administrator is only implemented on Windows; start aevand with sudo",
            executable.display()
        ))
    }

    pub fn spawn_detached(executable: &Path) -> std::io::Result<()> {
        std::process::Command::new(executable)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_child| ())
    }
}
