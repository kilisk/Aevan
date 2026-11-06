//! Let a Windows GUI-subsystem binary print into the terminal that launched it.
//!
//! A `windows_subsystem = "windows"` executable has no console of its own, so
//! `--version` and `--headless` would otherwise be silent when run from `cmd` or
//! PowerShell. When the standard handles were not already inherited (a pipe or
//! a file is also a valid inherited handle), attach to the parent's console and
//! point `stdout`/`stderr` at `CONOUT$` before the first print.
//!
//! This module is the only place in the GUI that calls Win32, and it does not
//! read or write any application data.

/// Attach to the launching terminal when it has one.
#[cfg(not(windows))]
pub fn attach_parent_console() {}

/// Attach to the launching terminal when it has one.
#[cfg(windows)]
pub fn attach_parent_console() {
    imp::attach_parent_console();
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::ffi::c_void;

    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
    const ATTACH_PARENT_PROCESS: u32 = -1i32 as u32;
    const FILE_TYPE_UNKNOWN: u32 = 0;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OPEN_EXISTING: u32 = 3;

    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn SetStdHandle(which: u32, handle: *mut c_void) -> i32;
        fn GetFileType(handle: *mut c_void) -> u32;
        fn CreateFileW(
            name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security: *mut c_void,
            creation: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
    }

    fn usable(handle: *mut c_void) -> bool {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return false;
        }
        // SAFETY: GetFileType only inspects the supplied handle and has no
        // other preconditions.
        unsafe { GetFileType(handle) != FILE_TYPE_UNKNOWN }
    }

    fn open_console_output() -> *mut c_void {
        let name: Vec<u16> = "CONOUT$".encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `name` is NUL-terminated; every other argument is a documented
        // constant for opening the active console output buffer.
        unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        }
    }

    pub fn attach_parent_console() {
        // Double-clicking from Explorer leaves no inherited console handles.
        // A redirected pipe or file is already usable and must not be replaced.
        // SAFETY: all four functions operate on the calling process's standard
        // handles; the returned handle is owned by the process for its lifetime.
        unsafe {
            let stdout = GetStdHandle(STD_OUTPUT_HANDLE);
            let stderr = GetStdHandle(STD_ERROR_HANDLE);
            let stdin = GetStdHandle(STD_INPUT_HANDLE);
            let need_stdout = !usable(stdout);
            let need_stderr = !usable(stderr);
            let need_stdin = !usable(stdin);

            if !(need_stdout || need_stderr || need_stdin) {
                return;
            }
            if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
                return;
            }
            if need_stdout {
                let handle = open_console_output();
                if usable(handle) {
                    SetStdHandle(STD_OUTPUT_HANDLE, handle);
                }
            }
            if need_stderr {
                let handle = open_console_output();
                if usable(handle) {
                    SetStdHandle(STD_ERROR_HANDLE, handle);
                }
            }
            if need_stdin {
                let name: Vec<u16> = "CONIN$".encode_utf16().chain(std::iter::once(0)).collect();
                let handle = CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                );
                if usable(handle) {
                    SetStdHandle(STD_INPUT_HANDLE, handle);
                }
            }
        }
    }
}
