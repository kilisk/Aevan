//! Explicit security descriptor for the Windows control pipe.
//!
//! `aevand` normally runs elevated because creating the WinTun adapter needs
//! Administrator. A named pipe created with the default descriptor by an
//! elevated process can only be opened by elevated clients, which surfaces as
//! Windows error 5 (`Access is denied`). The CLI is usually started from a
//! normal, medium-integrity shell, so the daemon must create the pipe with a
//! DACL that names the current interactive user and a mandatory label of
//! Medium.
//!
//! The descriptor is built from SDDL through
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW`, wrapped in
//! `SECURITY_ATTRIBUTES`, and passed to
//! `ServerOptions::create_with_security_attributes_raw`.
//!
//! # Why this module is allowed to use `unsafe`
//!
//! The crate denies `unsafe_code` everywhere else. The Win32 calls needed to
//! turn the SDDL string into a usable `SECURITY_ATTRIBUTES` are FFI
//! (`OpenProcessToken`, `GetTokenInformation`, `ConvertSidToStringSidW`,
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW` and `LocalFree`), and
//! `create_with_security_attributes_raw` is itself an unsafe function. There is
//! no safe-Rust API in `std` or in the crates this project already depends on
//! that sets a named-pipe DACL, so the exception is confined to the `ffi`
//! submodule below. If a checked, safe wrapper becomes available, it should
//! replace this module.

use std::fmt;
use std::io;

use aevan_core::AevanError;

/// Build the SDDL for the control pipe.
///
/// `D:(A;;GA;;;<sid>)` grants `sid` generic-all access. `S:(ML;;NW;;;ME)` sets
/// a Medium mandatory label with no-write-up, which is what lets a
/// medium-integrity client connect to a pipe owned by an elevated daemon.
///
/// Kept free of Win32 calls so the exact string can be tested on any host.
pub fn sddl_for_user(user_sid: &str) -> String {
    format!("D:(A;;GA;;;{user_sid})S:(ML;;NW;;;ME)")
}

/// A failure while preparing or creating a secured pipe instance.
#[derive(Debug)]
pub enum CreateError {
    /// The DACL could not be built. The daemon must refuse to start rather
    /// than fall back to the default descriptor.
    Security(io::Error),
    /// The pipe instance itself could not be created.
    Pipe(io::Error),
}

/// The error used when the daemon cannot apply the pipe DACL.
///
/// This is deliberately a hard failure: the default descriptor would deny the
/// normal CLI exactly when it matters, so silently using it would reintroduce
/// the original bug.
pub fn refuse_default_descriptor(reason: impl fmt::Display) -> AevanError {
    AevanError::Config(format!(
        "cannot apply the control pipe security descriptor: {reason}; refusing to start with \
         the default descriptor because a medium-integrity client could not connect to an \
         elevated aevand"
    ))
}

#[cfg(windows)]
mod ffi {
    #![allow(unsafe_code)]

    use std::ffi::c_void;
    use std::io;
    use std::ptr;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{sddl_for_user, CreateError};

    /// The SID of the user that owns the current process token.
    ///
    /// An elevated token keeps the same user SID as the medium-integrity token,
    /// so this is also the SID of the interactive user who will run `aevan`.
    pub fn current_user_sid() -> io::Result<String> {
        unsafe {
            let mut token: HANDLE = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let token = TokenHandle(token);

            let mut length = 0u32;
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut length);
            if length == 0 {
                return Err(io::Error::last_os_error());
            }

            // `Vec<usize>` keeps the buffer aligned for `TOKEN_USER`.
            let words = (length as usize).div_ceil(std::mem::size_of::<usize>());
            let mut buffer = vec![0usize; words];
            if GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }

            let user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let mut raw_sid: *mut u16 = ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut raw_sid) == 0 {
                return Err(io::Error::last_os_error());
            }

            let sid = wide_string(raw_sid);
            LocalFree(raw_sid.cast());
            sid
        }
    }

    /// Create one server instance with the explicit user DACL applied.
    ///
    /// Every instance is created with the descriptor, not only the first, so a
    /// client can never connect to an instance that fell back to the default
    /// security.
    pub fn create_server(
        addr: &str,
        first_instance: bool,
        user_sid: &str,
    ) -> Result<NamedPipeServer, CreateError> {
        let sddl = sddl_for_user(user_sid);
        let descriptor = SecurityDescriptor::from_sddl(&sddl).map_err(CreateError::Security)?;

        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };

        let mut options = ServerOptions::new();
        options.first_pipe_instance(first_instance);

        // Safety: `attributes` points at a live SECURITY_ATTRIBUTES whose
        // descriptor remains owned by `descriptor` until after the call
        // returns. `create_with_security_attributes_raw` copies what it needs
        // into the new pipe object.
        let result = unsafe {
            options.create_with_security_attributes_raw(
                addr,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        };
        result.map_err(CreateError::Pipe)
    }

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // Safety: the handle came from OpenProcessToken and is owned by
                // this guard.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct SecurityDescriptor(*mut c_void);

    impl SecurityDescriptor {
        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut descriptor: *mut c_void = ptr::null_mut();
            // Safety: `wide` is NUL-terminated and `descriptor` is a valid
            // out-pointer. The returned allocation is owned by the wrapper.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(descriptor))
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // Safety: the descriptor was allocated by
                // ConvertStringSecurityDescriptorToSecurityDescriptorW.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    fn wide_string(raw: *const u16) -> io::Result<String> {
        if raw.is_null() {
            return Err(io::Error::other("the user SID was empty"));
        }
        // Safety: ConvertSidToStringSidW returned a NUL-terminated wide string.
        unsafe {
            let mut length = 0usize;
            while *raw.add(length) != 0 {
                length += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(raw, length))
                .map_err(|_| io::Error::other("the user SID was not valid UTF-16"))
        }
    }
}

#[cfg(windows)]
pub use ffi::{create_server, current_user_sid};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_grants_the_user_and_a_medium_label() {
        let sddl = sddl_for_user("S-1-5-21-100-200-300-1001");
        assert_eq!(sddl, "D:(A;;GA;;;S-1-5-21-100-200-300-1001)S:(ML;;NW;;;ME)");
    }

    #[test]
    fn refusal_names_the_reason_and_never_falls_back() {
        let error = refuse_default_descriptor("the user SID could not be read");
        let message = error.to_string();
        assert!(
            message.contains("the user SID could not be read"),
            "{message}"
        );
        assert!(message.contains("refusing to start"), "{message}");
        assert!(message.contains("default descriptor"), "{message}");
        assert!(message.contains("medium-integrity"), "{message}");
        assert_eq!(error.exit_code(), 1);
    }
}
