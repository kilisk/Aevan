#![deny(unsafe_code)]
//! Per-user single-instance endpoint shared by `aevan-gui` and the `aevan`
//! launcher.
//!
//! The GUI owns one endpoint per user. The process that binds it is the primary
//! instance and serves `show` requests for its lifetime. Every later start
//! connects to that endpoint, sends one line `show` and exits without creating
//! a window or a tray icon.
//!
//! The endpoint name, the DACL (Windows) and the socket file (Unix) are the
//! same ones the daemon uses for its own control endpoint pattern. The Windows
//! pipe reuses `aevan_daemon::pipe_security`; no Win32 FFI is duplicated here.
//!
//! Everything testable is expressed through [`Endpoint`] and [`Listener`] so
//! unit tests never create a real pipe or socket.

use std::io;
use std::time::Duration;

/// How long a second instance waits for the endpoint before treating it as
/// stale.
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// The role this process has in the per-user instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceRole {
    /// This process bound the endpoint and owns the window/tray.
    Primary,
    /// Another process answered; this process asked it to show and must exit.
    Secondary,
}

/// The callback a listener invokes when a `show` line arrives.
pub type ShowHook = Box<dyn Fn() + Send + 'static>;

/// A bound endpoint that forwards `show` requests.
pub trait Listener: Send + 'static {
    /// Serve until the process exits. The primary instance calls this on a
    /// background thread.
    fn serve(self: Box<Self>, on_show: ShowHook);
}

/// The platform operations needed to claim the single-instance endpoint.
pub trait Endpoint {
    /// The listener created by a successful bind.
    type Listener: Listener;

    /// Try to become the primary instance.
    fn bind(&self) -> io::Result<Self::Listener>;

    /// Connect to an existing primary instance and send exactly one `show`
    /// line.
    fn send_show(&self, timeout: Duration) -> io::Result<()>;

    /// Remove a stale Unix socket file. A no-op on Windows, where the kernel
    /// releases the pipe name when its owner dies.
    fn remove_stale(&self) -> io::Result<()>;
}

/// The result of [`claim`].
#[derive(Debug)]
pub enum Claim<L> {
    /// The caller owns the endpoint and must serve the returned listener.
    Primary(L),
    /// Another instance was asked to show its window.
    Secondary,
}

/// Decide whether this process is the primary or a secondary instance.
///
/// 1. Try to bind. Success means primary.
/// 2. Otherwise connect and send `show`. Success means secondary.
/// 3. Otherwise the endpoint is stale: remove it (Unix), retry the bind once,
///    and become primary only if that succeeds. A failed retry is an error; it
///    never proceeds as a second window/tray.
pub fn claim<E: Endpoint>(endpoint: &E) -> io::Result<Claim<E::Listener>> {
    if let Ok(listener) = endpoint.bind() {
        return Ok(Claim::Primary(listener));
    }

    if endpoint.send_show(CONNECT_TIMEOUT).is_ok() {
        return Ok(Claim::Secondary);
    }

    let _ = endpoint.remove_stale();
    endpoint.bind().map(Claim::Primary).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot claim the GUI endpoint: {error}"),
        )
    })
}

/// Claim the platform endpoint and, when primary, serve it on a background
/// thread that forwards `show` requests into `on_show`.
pub fn claim_and_serve(on_show: ShowHook) -> io::Result<InstanceRole> {
    let endpoint = platform::endpoint()?;
    match claim(&endpoint)? {
        Claim::Secondary => Ok(InstanceRole::Secondary),
        Claim::Primary(listener) => {
            std::thread::Builder::new()
                .name("aevan-gui-instance".to_owned())
                .spawn(move || Box::new(listener).serve(on_show))
                .map_err(io::Error::other)?;
            Ok(InstanceRole::Primary)
        }
    }
}

/// Ask a running GUI to show its window. Returns an error when no instance is
/// listening.
pub fn show_running(timeout: Duration) -> io::Result<()> {
    platform::endpoint()?.send_show(timeout)
}

/// Human-readable endpoint used in diagnostics.
pub fn endpoint_description() -> String {
    platform::description()
}

#[cfg(windows)]
mod platform {
    use std::fs::OpenOptions;
    use std::io::{self, Write};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use tokio::io::AsyncBufReadExt;
    use tokio::net::windows::named_pipe::NamedPipeServer;

    use aevan_daemon::pipe_security::{self, CreateError};

    use super::{Endpoint, Listener, ShowHook};

    /// Name of the per-user GUI named pipe.
    pub const PIPE_NAME: &str = r"\\.\pipe\aevan-gui";

    /// How long a client retries `ERROR_PIPE_BUSY` before declaring failure.
    const OPEN_RETRY: Duration = Duration::from_millis(10);

    pub struct WindowsEndpoint;

    pub fn endpoint() -> io::Result<WindowsEndpoint> {
        Ok(WindowsEndpoint)
    }

    pub fn description() -> String {
        PIPE_NAME.to_owned()
    }

    pub struct WindowsListener {
        // The pipe instance is registered with this runtime's reactor, so the
        // runtime created during bind must travel with the listener.
        runtime: tokio::runtime::Runtime,
        server: NamedPipeServer,
        user_sid: String,
    }

    impl Listener for WindowsListener {
        fn serve(self: Box<Self>, on_show: ShowHook) {
            let WindowsListener {
                runtime,
                mut server,
                user_sid,
            } = *self;
            runtime.block_on(async move {
                loop {
                    if server.connect().await.is_err() {
                        // Keep the first-instance name owned: a transient
                        // connect error must never free it for a second GUI.
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }

                    // Publish the next listener instance before serving this
                    // connection, so a second launch never observes a gap.
                    let next = pipe_security::create_server(PIPE_NAME, false, &user_sid);

                    let mut line = String::new();
                    let mut reader = tokio::io::BufReader::new(&mut server);
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
                            .await;
                    drop(reader);

                    if line.trim() == "show" {
                        on_show();
                    }

                    match next {
                        Ok(next) => server = next,
                        Err(_) => return,
                    }
                }
            });
        }
    }

    impl Endpoint for WindowsEndpoint {
        type Listener = WindowsListener;

        fn bind(&self) -> io::Result<Self::Listener> {
            // Tokio registers a named-pipe instance with the current reactor,
            // so bind must happen inside the runtime that will serve it.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(io::Error::other)?;
            let user_sid = {
                let _guard = runtime.enter();
                pipe_security::current_user_sid()?
            };
            let server = {
                let _guard = runtime.enter();
                pipe_security::create_server(PIPE_NAME, true, &user_sid).map_err(|error| {
                    match error {
                        CreateError::Security(error) | CreateError::Pipe(error) => error,
                    }
                })?
            };
            Ok(WindowsListener {
                runtime,
                server,
                user_sid,
            })
        }

        fn send_show(&self, timeout: Duration) -> io::Result<()> {
            // Run the potentially blocking open/write on a worker so the
            // caller can enforce the short deadline even on a busy pipe.
            let (sender, receiver) = mpsc::channel();
            thread::spawn(move || {
                let _ = sender.send(write_show(timeout));
            });
            match receiver.recv_timeout(timeout) {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out asking the running aevan-gui to show its window",
                )),
            }
        }

        fn remove_stale(&self) -> io::Result<()> {
            // The kernel releases the pipe name when its owning process exits.
            Ok(())
        }
    }

    fn write_show(timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            match OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
                Ok(mut pipe) => {
                    pipe.write_all(b"show\n")?;
                    pipe.flush()?;
                    return Ok(());
                }
                Err(error) if is_pipe_busy(&error) && Instant::now() < deadline => {
                    thread::sleep(OPEN_RETRY);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn is_pipe_busy(error: &io::Error) -> bool {
        // ERROR_PIPE_BUSY
        error.raw_os_error() == Some(231)
    }
}

#[cfg(unix)]
mod platform {
    use std::fs;
    use std::io::{self, BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use aevan_core::paths;

    use super::{Endpoint, Listener, ShowHook};

    /// Socket file name inside the per-user configuration directory.
    pub const SOCKET_FILE: &str = "aevan-gui.sock";

    /// How long a client retries a transient connect failure.
    const CONNECT_RETRY: Duration = Duration::from_millis(10);

    pub struct UnixEndpoint {
        path: PathBuf,
    }

    pub fn endpoint() -> io::Result<UnixEndpoint> {
        let path = paths::config_dir()
            .map_err(|error| io::Error::other(error.to_string()))?
            .join(SOCKET_FILE);
        Ok(UnixEndpoint { path })
    }

    pub fn description() -> String {
        endpoint()
            .map(|endpoint| endpoint.path.display().to_string())
            .unwrap_or_else(|_| "unix socket in the config dir".to_owned())
    }

    pub struct UnixListenerHandle {
        listener: UnixListener,
    }

    impl Listener for UnixListenerHandle {
        fn serve(self: Box<Self>, on_show: ShowHook) {
            for connection in self.listener.incoming() {
                let Ok(mut stream) = connection else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut line = String::new();
                if BufReader::new(&mut stream).read_line(&mut line).is_ok() && line.trim() == "show"
                {
                    on_show();
                }
            }
        }
    }

    impl Endpoint for UnixEndpoint {
        type Listener = UnixListenerHandle;

        fn bind(&self) -> io::Result<Self::Listener> {
            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)?;
                if let Ok(metadata) = fs::metadata(parent) {
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o700);
                    let _ = fs::set_permissions(parent, permissions);
                }
            }

            let listener = UnixListener::bind(&self.path)?;
            if let Ok(metadata) = fs::metadata(&self.path) {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                let _ = fs::set_permissions(&self.path, permissions);
            }
            Ok(UnixListenerHandle { listener })
        }

        fn send_show(&self, timeout: Duration) -> io::Result<()> {
            let deadline = Instant::now() + timeout;
            loop {
                match UnixStream::connect(&self.path) {
                    Ok(mut stream) => {
                        stream.set_write_timeout(Some(timeout))?;
                        stream.write_all(b"show\n")?;
                        stream.flush()?;
                        return Ok(());
                    }
                    Err(error) if is_retryable(&error) && Instant::now() < deadline => {
                        std::thread::sleep(CONNECT_RETRY);
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        fn remove_stale(&self) -> io::Result<()> {
            match fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        }
    }

    fn is_retryable(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused | io::ErrorKind::WouldBlock
        )
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::io;

    use super::Endpoint;

    pub struct UnsupportedEndpoint;

    pub fn endpoint() -> io::Result<UnsupportedEndpoint> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no single-instance endpoint for this platform",
        ))
    }

    pub fn description() -> String {
        "unsupported single-instance endpoint".to_owned()
    }

    impl Endpoint for UnsupportedEndpoint {
        type Listener = UnsupportedListener;

        fn bind(&self) -> io::Result<Self::Listener> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no single-instance endpoint for this platform",
            ))
        }

        fn send_show(&self, _timeout: std::time::Duration) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no single-instance endpoint for this platform",
            ))
        }

        fn remove_stale(&self) -> io::Result<()> {
            Ok(())
        }
    }

    pub struct UnsupportedListener;

    impl super::Listener for UnsupportedListener {
        fn serve(self: Box<Self>, _on_show: super::ShowHook) {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{claim, Claim, Endpoint, Listener, ShowHook};

    #[derive(Default)]
    struct FakeState {
        bind_results: VecDeque<bool>,
        binds: usize,
        shows: usize,
        show_succeeds: bool,
        stale_removed: usize,
    }

    struct FakeEndpoint {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeEndpoint {
        fn fails_then_binds(show_succeeds: bool) -> Self {
            let mut state = FakeState {
                show_succeeds,
                ..FakeState::default()
            };
            // First bind fails (another instance), retry after cleanup succeeds.
            state.bind_results.push_back(false);
            state.bind_results.push_back(true);
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn always_binds() -> Self {
            let mut state = FakeState::default();
            state.bind_results.push_back(true);
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn in_use(show_succeeds: bool) -> Self {
            let mut state = FakeState {
                show_succeeds,
                ..FakeState::default()
            };
            state.bind_results.push_back(false);
            state.bind_results.push_back(false);
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }
    }

    struct FakeListener {
        shows: usize,
    }

    impl Listener for FakeListener {
        fn serve(self: Box<Self>, on_show: ShowHook) {
            for _ in 0..self.shows {
                on_show();
            }
        }
    }

    impl Endpoint for FakeEndpoint {
        type Listener = FakeListener;

        fn bind(&self) -> io::Result<Self::Listener> {
            let mut state = self.state.lock().expect("state");
            state.binds += 1;
            match state.bind_results.pop_front() {
                Some(true) => Ok(FakeListener { shows: 1 }),
                _ => Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "the endpoint is already owned",
                )),
            }
        }

        fn send_show(&self, _timeout: Duration) -> io::Result<()> {
            let mut state = self.state.lock().expect("state");
            state.shows += 1;
            if state.show_succeeds {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "nobody is listening",
                ))
            }
        }

        fn remove_stale(&self) -> io::Result<()> {
            self.state.lock().expect("state").stale_removed += 1;
            Ok(())
        }
    }

    #[test]
    fn a_successful_bind_makes_this_process_primary() {
        let endpoint = FakeEndpoint::always_binds();
        match claim(&endpoint).expect("claim") {
            Claim::Primary(_) => {}
            Claim::Secondary => panic!("first instance must be primary"),
        }
        let state = endpoint.state.lock().expect("state");
        assert_eq!(state.binds, 1);
        assert_eq!(state.shows, 0, "a primary never connects to itself");
        assert_eq!(state.stale_removed, 0);
    }

    #[test]
    fn an_answer_from_the_endpoint_makes_this_process_secondary() {
        let endpoint = FakeEndpoint::in_use(true);
        match claim(&endpoint).expect("claim") {
            Claim::Secondary => {}
            Claim::Primary(_) => panic!("second instance must not create a window"),
        }
        let state = endpoint.state.lock().expect("state");
        assert_eq!(state.shows, 1, "the second instance sends one show");
        assert_eq!(state.stale_removed, 0);
    }

    #[test]
    fn a_stale_endpoint_is_removed_and_the_bind_is_retried_once() {
        let endpoint = FakeEndpoint::fails_then_binds(false);
        match claim(&endpoint).expect("claim") {
            Claim::Primary(_) => {}
            Claim::Secondary => panic!("the stale endpoint must be replaced by a primary"),
        }
        let state = endpoint.state.lock().expect("state");
        assert_eq!(state.shows, 1, "the stale endpoint was probed first");
        assert_eq!(state.stale_removed, 1);
        assert_eq!(state.binds, 2, "the bind is retried exactly once");
    }

    #[test]
    fn a_show_request_reaches_the_hook() {
        let endpoint = FakeEndpoint::always_binds();
        let Claim::Primary(listener) = claim(&endpoint).expect("claim") else {
            panic!("expected primary");
        };

        let shown = Arc::new(AtomicBool::new(false));
        let hook_shown = shown.clone();
        Box::new(listener).serve(Box::new(move || {
            hook_shown.store(true, Ordering::SeqCst);
        }));

        assert!(shown.load(Ordering::SeqCst));
    }

    #[test]
    fn a_hopeless_endpoint_never_becomes_a_second_primary() {
        let endpoint = FakeEndpoint::in_use(false);
        assert!(claim(&endpoint).is_err());
        let state = endpoint.state.lock().expect("state");
        assert_eq!(state.binds, 2, "the bind is retried once and then refused");
    }

    #[test]
    fn the_test_hook_counter_is_observable() {
        // Guards against a test double silently doing nothing.
        let count = Arc::new(AtomicUsize::new(0));
        let listener = FakeListener { shows: 3 };
        let hook_count = count.clone();
        Box::new(listener).serve(Box::new(move || {
            hook_count.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}
