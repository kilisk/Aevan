//! POSIX readiness wait shared by the Linux and macOS backends.
//!
//! The data plane only needs `poll(2)` over the UDP socket and the device file
//! descriptor; the rest of those backends remain typed stubs.
#![allow(unsafe_code)]

use std::io;
use std::time::Duration;

use super::{Readiness, WaitHandle, WaitSources};

/// Wait for either descriptor with `poll(2)`.
pub fn wait_readable(sources: WaitSources, timeout: Duration) -> io::Result<Readiness> {
    if sources.udp.is_none() && sources.device.is_none() {
        std::thread::sleep(timeout);
        return Ok(Readiness::default());
    }

    let mut fds = [libc::pollfd {
        fd: -1,
        events: 0,
        revents: 0,
    }; 2];
    let mut count = 0usize;
    let mut udp_slot = None;
    let mut device_slot = None;

    if let Some(fd) = sources.udp {
        udp_slot = Some(count);
        fds[count] = libc::pollfd {
            fd: fd as libc::c_int,
            events: libc::POLLIN,
            revents: 0,
        };
        count += 1;
    }
    if let Some(fd) = sources.device {
        device_slot = Some(count);
        fds[count] = libc::pollfd {
            fd: fd as libc::c_int,
            events: libc::POLLIN,
            revents: 0,
        };
        count += 1;
    }

    let millis = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    // SAFETY: `fds` has `count` initialised entries and `poll` only writes
    // their `revents` fields.
    let result = unsafe { libc::poll(fds.as_mut_ptr(), count as libc::nfds_t, millis) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(Readiness::default());
        }
        return Err(error);
    }

    let mut readiness = Readiness::default();
    if result > 0 {
        if let Some(slot) = udp_slot {
            readiness.udp = fds[slot].revents != 0;
        }
        if let Some(slot) = device_slot {
            readiness.device = fds[slot].revents != 0;
        }
    }
    Ok(readiness)
}

/// Request 4 MiB send and receive buffers, ignoring failure.
pub fn tune_udp_socket(handle: WaitHandle) {
    const BUFFER_BYTES: libc::c_int = 4 * 1024 * 1024;
    let fd = handle as libc::c_int;
    let value = BUFFER_BYTES;
    let pointer = std::ptr::addr_of!(value).cast();
    let length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is the caller's live socket and the option value outlives
    // both calls. Errors are deliberately ignored.
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, pointer, length);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, pointer, length);
    }
}
