//! Start the sibling daemon with one UAC prompt and launch the GUI detached.
//!
//! On Windows the only way to create the Wintun adapter without a manual
//! elevated terminal is to ask the shell to start `aevand.exe` with the
//! `runas` verb. The Win32 call is confined to [`imp`] and kept free of any
//! credential handling: the daemon is only a listener until a control request
//! arrives.
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

/// A captured elevated command: what ran, how it exited and what it said.
///
/// The daemon-start log uses this to name a failure. It deliberately carries
/// only the command, status and stderr; callers never put credentials in an
/// elevated start command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptOutcome {
    /// The exact shell command passed to the administrator prompt.
    pub command: String,
    /// The outcome classification used by existing callers.
    pub outcome: StartOutcome,
    /// The process exit status, when one was observed.
    pub exit_status: Option<i32>,
    /// Captured stderr, verbatim.
    pub stderr: String,
}

/// Start `executable` with `args` elevated.
///
/// Windows shows the single UAC prompt. Other platforms report that this is
/// unsupported; the CLI prints the normal guidance to start `aevand` manually.
pub fn start_elevated(executable: &Path, args: &[&str]) -> StartOutcome {
    imp::start_elevated(executable, args)
}

/// Run one shell command behind a single native administrator prompt.
///
/// macOS uses `osascript`; every other platform reports that this is
/// unsupported. The command is expected to set a non-zero exit on failure so
/// the platform reports [`StartOutcome::Failed`] with the tool's own message.
pub fn run_script_elevated(script: &str) -> StartOutcome {
    run_script_elevated_captured(script).outcome
}

/// Run one shell command behind a single native administrator prompt and
/// return its command, exit status and stderr for diagnostics.
pub fn run_script_elevated_captured(script: &str) -> ScriptOutcome {
    imp::run_script_elevated_captured(script)
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

    use super::{ScriptOutcome, StartOutcome};

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

    pub fn run_script_elevated_captured(script: &str) -> ScriptOutcome {
        ScriptOutcome {
            command: script.to_owned(),
            outcome: StartOutcome::Failed(
                "administrator shell scripts are only implemented on macOS".into(),
            ),
            exit_status: None,
            stderr: String::new(),
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::OsStr;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::Command;

    use super::{ScriptOutcome, StartOutcome};

    /// Quote one argument for `/bin/sh` using single quotes.
    fn posix_quote(value: &OsStr) -> String {
        let text = value.to_string_lossy();
        let mut quoted = String::with_capacity(text.len() + 2);
        quoted.push('\'');
        for character in text.chars() {
            if character == '\'' {
                quoted.push_str("'\\''");
            } else {
                quoted.push(character);
            }
        }
        quoted.push('\'');
        quoted
    }

    /// Quote a whole command line as an AppleScript string literal.
    fn apple_script_quote(value: &str) -> String {
        let mut quoted = String::with_capacity(value.len() + 2);
        quoted.push('"');
        for character in value.chars() {
            match character {
                '\\' => quoted.push_str("\\\\"),
                '"' => quoted.push_str("\\\""),
                _ => quoted.push(character),
            }
        }
        quoted.push('"');
        quoted
    }

    /// Build the shell command that starts the sibling daemon.
    ///
    /// The daemon runs as root because creating `utun` needs it, but the GUI
    /// and CLI run as the installing user. Point the daemon at that user's
    /// config directory and, once the socket exists, give the directory and
    /// socket back to the user so the GUI can connect.
    fn command_line(executable: &Path, args: &[&str]) -> String {
        let config_dir = aevan_core::paths::config_dir().ok();
        let mut command = String::new();
        if let Some(dir) = config_dir.as_deref() {
            command.push_str("AEVAN_CONFIG_DIR=");
            command.push_str(&posix_quote(dir.as_os_str()));
            command.push(' ');
        }
        command.push_str("/usr/bin/nohup ");
        command.push_str(&posix_quote(executable.as_os_str()));
        for argument in args {
            command.push(' ');
            command.push_str(&posix_quote(OsStr::new(argument)));
        }
        command.push_str(" </dev/null >/dev/null 2>&1 &");

        if let (Some(dir), Some(home)) = (config_dir.as_deref(), std::env::var_os("HOME")) {
            if let Ok(metadata) = std::fs::metadata(home) {
                let socket = dir.join("aevan.sock");
                command.push_str(&format!(
                    " i=0; while [ $i -lt 50 ] && [ ! -S {} ]; do i=$((i+1)); /bin/sleep 0.1; done; /usr/bin/chown {} {} {} 2>/dev/null || true",
                    posix_quote(socket.as_os_str()),
                    metadata.uid(),
                    posix_quote(dir.as_os_str()),
                    posix_quote(socket.as_os_str()),
                ));
            }
        }
        command
    }

    pub fn start_elevated(executable: &Path, args: &[&str]) -> StartOutcome {
        run_script_elevated_captured(&command_line(executable, args)).outcome
    }

    pub fn run_script_elevated_captured(command: &str) -> ScriptOutcome {
        let script = format!(
            "do shell script {} with administrator privileges",
            apple_script_quote(command)
        );

        let output = match Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(&script)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                let stderr = format!("could not run osascript: {error}");
                return ScriptOutcome {
                    command: command.to_owned(),
                    outcome: StartOutcome::Failed(stderr.clone()),
                    exit_status: None,
                    stderr,
                };
            }
        };
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let exit_status = output.status.code();
        let outcome = if output.status.success() {
            StartOutcome::Started
        } else {
            let lowered = stderr.to_ascii_lowercase();
            if lowered.contains("user canceled")
                || lowered.contains("user cancelled")
                || stderr.contains("(-128)")
            {
                StartOutcome::Cancelled
            } else {
                let detail = stderr.trim();
                if detail.is_empty() {
                    StartOutcome::Failed(
                        "macOS refused the administrator command without a reason".into(),
                    )
                } else {
                    StartOutcome::Failed(format!(
                        "macOS refused the administrator command: {detail}"
                    ))
                }
            }
        };
        ScriptOutcome {
            command: command.to_owned(),
            outcome,
            exit_status,
            stderr,
        }
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

    use super::{ScriptOutcome, StartOutcome};

    pub fn start_elevated(executable: &Path, _args: &[&str]) -> StartOutcome {
        StartOutcome::Failed(format!(
            "starting {} with Administrator is only implemented on Windows and macOS; start aevand with sudo",
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

    pub fn run_script_elevated_captured(_script: &str) -> ScriptOutcome {
        ScriptOutcome {
            command: String::new(),
            outcome: StartOutcome::Failed(
                "administrator shell scripts are only implemented on macOS".into(),
            ),
            exit_status: None,
            stderr: String::new(),
        }
    }
}
