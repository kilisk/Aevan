//! A dedicated blocking-read thread for the Unix tunnel descriptor.
//!
//! This is the WireGuard pattern: one thread owns the read side of the
//! `utun`/`tun` descriptor and performs blocking `read(2)` calls. Packets are
//! handed to the ESP loop over a bounded channel. The loop never polls or reads
//! the descriptor itself, so a readable-but-empty `poll(2)` cannot stop the
//! interface queue from draining.
//!
//! Cancellation uses a self-pipe rather than closing the descriptor from
//! another thread: the reader waits in `poll(2)` on the tunnel descriptor and
//! the pipe's read end, then reads the descriptor. Shutdown writes one byte to
//! the pipe, so the reader leaves `poll` promptly even when no packet arrives.
//! The descriptor itself stays blocking, which is what makes the post-`poll`
//! read return the packet instead of `EAGAIN`.
//!
//! A reader that cannot be joined within [`JOIN_TIMEOUT`] is detached and
//! logged; a wedged reader never prevents route or DNS rollback.
#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::device::Device;
use crate::error::TunError;

/// Capacity of the queue between the reader thread and the ESP loop.
pub const DEVICE_CHANNEL_CAPACITY: usize = 256;

/// How long shutdown waits for the reader thread to finish.
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Largest frame read from the kernel: a full IPv6 packet plus the utun header.
const MAX_FRAME: usize = 4 + 65_536;

/// How often a full-channel warning is emitted.
const FULL_WARNING_INTERVAL: Duration = Duration::from_secs(1);

/// One blocking packet source for the reader thread.
///
/// The real source reads an OS descriptor; tests supply an in-memory source
/// that blocks after its queued packets are consumed.
pub trait PacketSource: Send {
    /// Block until one packet is available and write it into `buffer`.
    ///
    /// A return of zero means end of file or cancellation. `Interrupted` is
    /// retried by the reader loop.
    fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize>;

    /// A handle that wakes a pending [`Self::read_packet`] and makes it return
    /// zero. Calling it more than once is harmless.
    fn wake_handle(&self) -> Box<dyn Fn() + Send + Sync>;
}

/// The queue consumer plus the reader thread's lifecycle.
pub struct DeviceReader {
    rx: Receiver<Vec<u8>>,
    dead: Arc<AtomicBool>,
    wake: Box<dyn Fn() + Send + Sync>,
    join: Option<JoinHandle<()>>,
    interface: String,
    fd: Option<isize>,
    pipe: Option<(RawFd, RawFd)>,
}

impl DeviceReader {
    /// Start a reader for a device that exposes a Unix descriptor.
    ///
    /// Returns `Ok(None)` when the backend has no waitable descriptor, which is
    /// the case for the in-memory backends and for Windows.
    pub fn spawn_device(device: &dyn Device) -> io::Result<Option<Self>> {
        let Some(handle) = device.wait_handle() else {
            return Ok(None);
        };
        let interface = device.name().unwrap_or("tun").to_owned();
        let fd = handle as RawFd;
        let (wake_read, wake_write) = make_pipe()?;
        let source = Box::new(FdSource {
            fd,
            wake_read,
            wake_write,
        });
        let wake: Box<dyn Fn() + Send + Sync> = {
            let wake_write = wake_write;
            Box::new(move || wake_pipe(wake_write))
        };
        match Self::spawn_inner(source, interface, Some(handle), wake, Some((wake_read, wake_write))) {
            Ok(reader) => Ok(Some(reader)),
            Err(error) => {
                close_fd(wake_read);
                close_fd(wake_write);
                Err(error)
            }
        }
    }

    /// Start a reader from a custom source.
    ///
    /// Used by tests and by backends whose packet source is not a raw
    /// descriptor. The source's own wake handle is used for shutdown.
    #[doc(hidden)]
    pub fn spawn_source(
        source: Box<dyn PacketSource>,
        interface: String,
        fd: Option<isize>,
    ) -> io::Result<Self> {
        let wake = source.wake_handle();
        Self::spawn_inner(source, interface, fd, wake, None)
    }

    fn spawn_inner(
        source: Box<dyn PacketSource>,
        interface: String,
        fd: Option<isize>,
        wake: Box<dyn Fn() + Send + Sync>,
        pipe: Option<(RawFd, RawFd)>,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(DEVICE_CHANNEL_CAPACITY);
        let dead = Arc::new(AtomicBool::new(false));
        let reader_dead = Arc::clone(&dead);
        let reader_interface = interface.clone();
        let join = thread::Builder::new()
            .name("aevan-tun-reader".to_owned())
            .spawn(move || reader_loop(source, tx, reader_dead, reader_interface))?;
        tracing::info!(
            interface = %interface,
            fd = ?fd,
            capacity = DEVICE_CHANNEL_CAPACITY,
            "tunnel device reader started"
        );
        Ok(Self {
            rx,
            dead,
            wake,
            join: Some(join),
            interface,
            fd,
            pipe,
        })
    }

    /// Take the next packet without waiting. `None` means the queue is empty.
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        self.rx.try_recv().ok()
    }

    /// Whether the reader stopped because the descriptor failed or reached EOF.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// The interface name the OS assigned.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The descriptor the reader holds.
    pub const fn fd(&self) -> Option<isize> {
        self.fd
    }

    /// Wake the reader and join it, bounded by [`JOIN_TIMEOUT`].
    ///
    /// Returns whether the thread was joined. A `false` result means the
    /// reader was detached so teardown can continue.
    pub fn shutdown(&mut self) -> bool {
        (self.wake)();
        let joined = match self.join.take() {
            Some(handle) => join_with_timeout(handle, JOIN_TIMEOUT),
            None => true,
        };
        if joined {
            if let Some((wake_read, wake_write)) = self.pipe.take() {
                close_fd(wake_read);
                close_fd(wake_write);
            }
            tracing::debug!(
                interface = %self.interface,
                fd = ?self.fd,
                "tunnel device reader stopped"
            );
        } else {
            tracing::warn!(
                interface = %self.interface,
                fd = ?self.fd,
                timeout = ?JOIN_TIMEOUT,
                "tunnel device reader did not stop in time; detaching it so teardown can continue"
            );
        }
        joined
    }
}

impl Drop for DeviceReader {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn reader_loop(
    mut source: Box<dyn PacketSource>,
    sender: SyncSender<Vec<u8>>,
    dead: Arc<AtomicBool>,
    interface: String,
) {
    let mut buffer = vec![0u8; MAX_FRAME];
    let mut last_full_warning: Option<Instant> = None;
    loop {
        match source.read_packet(&mut buffer) {
            Ok(0) => {
                tracing::debug!(interface = %interface, "tunnel device reader reached end of input");
                return;
            }
            Ok(length) => {
                let packet = match packet_bytes(&buffer[..length]) {
                    Ok(packet) => packet,
                    Err(error) => {
                        tracing::warn!(
                            interface = %interface,
                            %error,
                            "dropping a malformed tunnel frame"
                        );
                        continue;
                    }
                };
                match sender.try_send(packet.to_vec()) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        let now = Instant::now();
                        if last_full_warning
                            .is_none_or(|at| now.duration_since(at) >= FULL_WARNING_INTERVAL)
                        {
                            tracing::warn!(
                                interface = %interface,
                                capacity = DEVICE_CHANNEL_CAPACITY,
                                "tunnel device channel is full; dropping packet"
                            );
                            last_full_warning = Some(now);
                        }
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                dead.store(true, Ordering::Release);
                tracing::warn!(
                    interface = %interface,
                    kind = ?error.kind(),
                    %error,
                    "tunnel device reader stopped after a read error"
                );
                return;
            }
        }
    }
}

/// Validate a frame read from the descriptor and return the inner IP packet.
fn packet_bytes(frame: &[u8]) -> Result<&[u8], TunError> {
    #[cfg(target_os = "macos")]
    {
        crate::platform::macos::strip_frame(frame)
    }
    #[cfg(not(target_os = "macos"))]
    {
        if frame.is_empty() {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "the tunnel descriptor returned an empty packet",
            )));
        }
        Ok(frame)
    }
}

struct FdSource {
    fd: RawFd,
    wake_read: RawFd,
    wake_write: RawFd,
}

impl PacketSource for FdSource {
    fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut descriptors = [
                libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.wake_read,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: `descriptors` has two initialised entries; `poll` only
            // writes their `revents` fields. A negative timeout waits forever.
            let ready = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if descriptors[1].revents != 0 {
                return Ok(0);
            }
            if descriptors[0].revents
                & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                == 0
            {
                continue;
            }
            // SAFETY: `self.fd` stays open for the life of the source and
            // `buffer` is exclusively borrowed writable storage.
            let length = unsafe {
                libc::read(
                    self.fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if length < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            return Ok(length as usize);
        }
    }

    fn wake_handle(&self) -> Box<dyn Fn() + Send + Sync> {
        let wake_write = self.wake_write;
        Box::new(move || wake_pipe(wake_write))
    }
}

fn make_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut descriptors = [0 as RawFd; 2];
    // SAFETY: `descriptors` holds two writable slots for the two descriptors
    // the kernel returns.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    set_cloexec(descriptors[0]);
    set_cloexec(descriptors[1]);
    set_nonblocking(descriptors[1]);
    Ok((descriptors[0], descriptors[1]))
}

fn set_cloexec(fd: RawFd) {
    // SAFETY: `fd` is a live descriptor owned by this module.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags >= 0 {
        // SAFETY: same live descriptor.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

fn set_nonblocking(fd: RawFd) {
    // SAFETY: `fd` is the wake pipe's write end, owned by this module.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        // SAFETY: same live descriptor.
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

fn wake_pipe(fd: RawFd) {
    let byte = 1u8;
    // SAFETY: `fd` is the wake pipe's non-blocking write end. A full pipe or a
    // closed descriptor is harmless: the reader is already leaving.
    unsafe {
        libc::write(fd, std::ptr::addr_of!(byte).cast::<libc::c_void>(), 1);
    }
}

fn close_fd(fd: RawFd) {
    // SAFETY: `fd` is owned by this module and is closed exactly once.
    unsafe {
        libc::close(fd);
    }
}

fn join_with_timeout(handle: JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(2));
    }
    let _ = handle.join();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ipv4_packet(marker: u8) -> Vec<u8> {
        vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0,
            marker, 10, 0, 0, 2,
        ]
    }

    fn utun_frame(packet: &[u8]) -> Vec<u8> {
        let mut frame = 2u32.to_be_bytes().to_vec();
        frame.extend_from_slice(packet);
        frame
    }

    #[derive(Clone, Default)]
    struct BlockingSource {
        packets: Arc<Mutex<VecDeque<Vec<u8>>>>,
        stopped: Arc<(Mutex<bool>, Condvar)>,
        reads: Arc<Mutex<usize>>,
    }

    impl BlockingSource {
        fn with_packets(packets: Vec<Vec<u8>>) -> Self {
            Self {
                packets: Arc::new(Mutex::new(packets.into())),
                stopped: Arc::new((Mutex::new(false), Condvar::new())),
                reads: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl PacketSource for BlockingSource {
        fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if let Some(packet) = self.packets.lock().expect("packets").pop_front() {
                assert!(packet.len() <= buffer.len());
                buffer[..packet.len()].copy_from_slice(&packet);
                *self.reads.lock().expect("reads") += 1;
                return Ok(packet.len());
            }
            let (lock, condition) = &*self.stopped;
            let mut stopped = lock.lock().expect("stopped");
            while !*stopped {
                stopped = condition.wait(stopped).expect("stopped wait");
            }
            Ok(0)
        }

        fn wake_handle(&self) -> Box<dyn Fn() + Send + Sync> {
            let stopped = Arc::clone(&self.stopped);
            Box::new(move || {
                let (lock, condition) = &*stopped;
                *lock.lock().expect("stopped") = true;
                condition.notify_all();
            })
        }
    }

    fn wait_for_packets(reader: &DeviceReader, count: usize) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut packets = Vec::new();
        while packets.len() < count && Instant::now() < deadline {
            match reader.try_recv() {
                Some(packet) => packets.push(packet),
                None => thread::sleep(Duration::from_millis(1)),
            }
        }
        packets
    }

    #[test]
    fn a_blocking_source_delivers_both_queued_packets_then_the_queue_is_empty() {
        let first = ipv4_packet(1);
        let second = ipv4_packet(2);
        let source = BlockingSource::with_packets(vec![utun_frame(&first), utun_frame(&second)]);
        let reads = Arc::clone(&source.reads);
        let mut reader = DeviceReader::spawn_source(
            Box::new(source),
            "utun-test".to_owned(),
            Some(11),
        )
        .expect("reader");

        let packets = wait_for_packets(&reader, 2);
        assert_eq!(packets.len(), 2, "both queued packets must arrive");
        assert_eq!(packets[0], first);
        assert_eq!(packets[1], second);
        assert_eq!(*reads.lock().expect("reads"), 2);

        // The source is now blocked, but the consumer must not wait for it.
        let started = Instant::now();
        assert!(reader.try_recv().is_none());
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "an empty queue must return immediately even while the reader blocks"
        );
        assert!(!reader.is_dead());

        let started = Instant::now();
        assert!(reader.shutdown(), "shutdown must join the reader");
        assert!(started.elapsed() < JOIN_TIMEOUT + Duration::from_millis(50));
    }

    #[test]
    fn shutdown_is_idempotent() {
        let source = BlockingSource::with_packets(Vec::new());
        let mut reader =
            DeviceReader::spawn_source(Box::new(source), "utun-test".to_owned(), None)
                .expect("reader");
        assert!(reader.shutdown());
        assert!(reader.shutdown(), "a second shutdown is still joined");
    }

    #[test]
    fn malformed_frames_are_dropped_without_stopping_the_reader() {
        let good = ipv4_packet(7);
        let mut short = vec![0u8, 0, 2];
        short.extend_from_slice(&[0x45]);
        let source = BlockingSource::with_packets(vec![short, utun_frame(&good)]);
        let mut reader =
            DeviceReader::spawn_source(Box::new(source), "utun-test".to_owned(), None)
                .expect("reader");

        let packets = wait_for_packets(&reader, 1);
        assert_eq!(packets, vec![good]);
        assert!(reader.shutdown());
    }

    #[test]
    fn a_reader_error_sets_the_dead_flag() {
        struct Failing;
        impl PacketSource for Failing {
            fn read_packet(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn wake_handle(&self) -> Box<dyn Fn() + Send + Sync> {
                Box::new(|| {})
            }
        }

        let mut reader =
            DeviceReader::spawn_source(Box::new(Failing), "utun-test".to_owned(), None)
                .expect("reader");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !reader.is_dead() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(reader.is_dead(), "a read error must mark the reader dead");
        assert!(reader.shutdown());
    }

    #[test]
    fn the_test_packets_are_valid_ipv4() {
        assert_eq!(ipv4_packet(0x2a)[0] >> 4, 4);
        assert_eq!(Ipv4Addr::new(10, 0, 0, 2).octets()[0], 10);
    }
}
