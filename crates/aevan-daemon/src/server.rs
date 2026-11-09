//! Control endpoint: a Unix socket or the Windows named pipe `\\.\pipe\aevan`.
//!
//! The listener accepts one connection at a time and each connection speaks the
//! versioned JSON-line protocol. `logs --follow` keeps a connection open for the
//! lifetime of the stream; every other command returns one response line.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;

use aevan_core::{AevanError, AevanResult};

use crate::logs::Level;
use crate::protocol::{encode_line, Request, Response, MAX_LINE_BYTES, SCHEMA_VERSION};
use crate::runtime::Daemon;

/// Name of the Windows named pipe.
#[cfg(windows)]
pub const PIPE_NAME: &str = r"\\.\pipe\aevan";

/// Unix socket file name inside the config or system directory.
#[cfg(unix)]
pub const SOCKET_FILE: &str = "aevan.sock";

/// The per-user control socket, beside the profile store.
#[cfg(unix)]
pub fn per_user_endpoint_path() -> AevanResult<PathBuf> {
    Ok(aevan_core::paths::config_dir()?.join(SOCKET_FILE))
}

/// The machine-wide control socket a root daemon binds.
///
/// `None` on platforms without a Unix socket.
#[cfg(target_os = "macos")]
pub fn system_endpoint_path() -> Option<PathBuf> {
    Some(PathBuf::from("/Library/Application Support/Aevan").join(SOCKET_FILE))
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn system_endpoint_path() -> Option<PathBuf> {
    Some(PathBuf::from("/run/aevan").join(SOCKET_FILE))
}

#[cfg(not(unix))]
pub fn system_endpoint_path() -> Option<PathBuf> {
    None
}

/// The endpoints a client tries, in order: system first, then per-user.
///
/// The list is built without touching the filesystem or opening a socket so it
/// can be unit-tested everywhere.
#[cfg(unix)]
pub fn candidate_endpoints() -> AevanResult<Vec<PathBuf>> {
    // A client whose HOME cannot be resolved (cron, launchd, a stripped shell)
    // must still be able to reach a root daemon on the system endpoint.
    let per_user = per_user_endpoint_path().ok();
    ordered_candidates_optional(system_endpoint_path(), per_user)
}

#[cfg(unix)]
fn ordered_candidates_optional(
    system: Option<PathBuf>,
    per_user: Option<PathBuf>,
) -> AevanResult<Vec<PathBuf>> {
    let mut candidates = Vec::with_capacity(2);
    if let Some(system) = system {
        candidates.push(system);
    }
    if let Some(per_user) = per_user {
        if !candidates.contains(&per_user) {
            candidates.push(per_user);
        }
    }
    if candidates.is_empty() {
        return Err(AevanError::Config(
            "no control endpoint is available; HOME is unset and this platform has no system socket"
                .into(),
        ));
    }
    Ok(candidates)
}

#[cfg(not(unix))]
pub fn candidate_endpoints() -> AevanResult<Vec<PathBuf>> {
    Ok(Vec::new())
}

/// Select the binding endpoint for a daemon: system when root, per-user
/// otherwise. Pure so the root/non-root split is testable without a real uid.
#[cfg(all(unix, test))]
fn select_binding_endpoint(root: bool, system: Option<PathBuf>, per_user: PathBuf) -> PathBuf {
    match (root, system) {
        (true, Some(system)) => system,
        _ => per_user,
    }
}

/// Path of the Unix control socket the daemon should bind.
///
/// A root daemon (including one started by launchd) uses the machine-wide
/// endpoint; a user daemon keeps the per-user endpoint.
#[cfg(unix)]
pub fn endpoint_path() -> AevanResult<PathBuf> {
    endpoint_path_for_root(process_is_root())
}

#[cfg(unix)]
pub fn endpoint_path_for_root(root: bool) -> AevanResult<PathBuf> {
    // A root daemon binds the machine-wide endpoint and must not depend on the
    // per-user one: launchd starts system daemons with no HOME, and resolving
    // $HOME there used to fail the whole call, so aevand exited 1 before it
    // ever opened a socket.
    match (root, system_endpoint_path()) {
        (true, Some(system)) => Ok(system),
        _ => per_user_endpoint_path(),
    }
}

/// Whether `path` is the machine-wide system endpoint.
#[cfg(unix)]
pub fn is_system_endpoint(path: &std::path::Path) -> bool {
    system_endpoint_path().is_some_and(|system| system == path)
}

#[cfg(unix)]
fn process_is_root() -> bool {
    unix_uid::is_root()
}

#[cfg(unix)]
mod unix_uid {
    //! The crate denies `unsafe_code`; `geteuid` is the only call needed here
    //! and it has no preconditions.
    #![allow(unsafe_code)]

    pub fn is_root() -> bool {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
}

/// The error used when another daemon already owns the control endpoint.
pub fn already_listening(endpoint: &str) -> AevanError {
    AevanError::AlreadyInState(format!(
        "another aevand is already listening on {endpoint}; stop it first"
    ))
}

/// Human-readable endpoint for logs and CLI errors.
pub fn endpoint_description() -> String {
    #[cfg(unix)]
    {
        match endpoint_path() {
            Ok(path) => path.display().to_string(),
            Err(_) => "unix socket in the config dir".to_owned(),
        }
    }
    #[cfg(windows)]
    {
        PIPE_NAME.to_owned()
    }
    #[cfg(not(any(unix, windows)))]
    {
        "unsupported control endpoint".to_owned()
    }
}

/// Serve the control protocol until a `shutdown` request.
pub async fn serve(daemon: Arc<Daemon>) -> AevanResult<()> {
    platform_serve(daemon).await
}

async fn handle_connection<S>(stream: S, daemon: Arc<Daemon>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Err(error) = serve_connection(stream, daemon).await {
        tracing::debug!(%error, "control connection ended");
    }
}

/// Serve one control connection. Public so tests can use an in-memory duplex.
pub async fn serve_connection<S>(stream: S, daemon: Arc<Daemon>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            return Ok(());
        }
        if line.len() > MAX_LINE_BYTES {
            let response = Response::protocol_error(
                "unknown",
                format!("request line exceeds {MAX_LINE_BYTES} bytes"),
                AevanError::Config("request too large".into()).exit_code(),
            );
            write_response(&mut write, &response, SCHEMA_VERSION).await?;
            continue;
        }

        let request: Request = match serde_json::from_str(line.trim()) {
            Ok(request) => request,
            Err(error) => {
                let response = Response::protocol_error(
                    "unknown",
                    format!("invalid request JSON: {error}"),
                    AevanError::Config("invalid request".into()).exit_code(),
                );
                write_response(&mut write, &response, SCHEMA_VERSION).await?;
                continue;
            }
        };

        if !request.schema_supported() {
            let error = AevanError::Unsupported(format!(
                "protocol schema {} is not supported (expected {})",
                request.schema_version,
                crate::protocol::SCHEMA_VERSION
            ));
            let response = Response::error(&request.command, &error);
            write_response(&mut write, &response, SCHEMA_VERSION).await?;
            continue;
        }

        // A version-1 client only understands version-1 responses, so answer
        // in the version the request used. This build sends 2.
        let schema_version = request.schema_version;
        let command = request.command.clone();
        match command.as_str() {
            "status" => {
                let response = Response::status("status", daemon.snapshot());
                write_response(&mut write, &response, schema_version).await?;
            }
            "connect" => {
                let password = match request.password {
                    Some(password) => password.into_inner(),
                    None => {
                        let error = AevanError::Config(
                            "connect request is missing the password field".into(),
                        );
                        write_response(
                            &mut write,
                            &Response::error("connect", &error),
                            schema_version,
                        )
                        .await?;
                        continue;
                    }
                };
                let token = request.token.map(|token| token.into_inner());
                match daemon
                    .connect(
                        request.profile,
                        request.gateway_url,
                        request.realm,
                        request.username,
                        password,
                        token,
                    )
                    .await
                {
                    Ok(status) => {
                        let response = Response::status("connect", status);
                        write_response(&mut write, &response, schema_version).await?;
                    }
                    Err(error) => {
                        write_response(
                            &mut write,
                            &Response::error("connect", &error),
                            schema_version,
                        )
                        .await?;
                    }
                }
            }
            "disconnect" => {
                match daemon
                    .disconnect(request.profile.as_deref(), request.all)
                    .await
                {
                    Ok(status) => {
                        let response = Response::status("disconnect", status);
                        write_response(&mut write, &response, schema_version).await?;
                    }
                    Err(error) => {
                        write_response(
                            &mut write,
                            &Response::error("disconnect", &error),
                            schema_version,
                        )
                        .await?;
                    }
                }
            }
            "recover" => match daemon.recover().await {
                Ok(report) => {
                    let response = Response::recovered("recover", daemon.snapshot(), report);
                    write_response(&mut write, &response, schema_version).await?;
                }
                Err(error) => {
                    write_response(
                        &mut write,
                        &Response::error("recover", &error),
                        schema_version,
                    )
                    .await?;
                }
            },
            "logs" => {
                if !stream_logs(&daemon, &request, &mut write).await? {
                    return Ok(());
                }
            }
            "shutdown" => {
                write_response(&mut write, &Response::ok("shutdown"), schema_version).await?;
                daemon.request_shutdown();
                return Ok(());
            }
            other => {
                let error = AevanError::Config(format!("unknown command '{other}'"));
                write_response(&mut write, &Response::error(other, &error), schema_version).await?;
            }
        }

        if daemon.is_shutdown_requested() {
            return Ok(());
        }
    }
}

async fn stream_logs<W>(daemon: &Arc<Daemon>, request: &Request, writer: &mut W) -> io::Result<bool>
where
    W: AsyncWrite + Unpin,
{
    let level = match request.level.as_deref() {
        Some(name) => match Level::parse(name) {
            Some(level) => level,
            None => {
                let error = AevanError::Config(format!(
                    "unknown log level '{name}' (use error, warn, info, debug or trace)"
                ));
                write_response(
                    writer,
                    &Response::error("logs", &error),
                    request.schema_version,
                )
                .await?;
                return Ok(true);
            }
        },
        None => Level::Info,
    };

    let mut receiver = daemon.logs().subscribe();
    let mut last_seq = 0;
    for record in daemon.logs().history(level) {
        last_seq = record.seq;
        write_response(
            writer,
            &Response::record("logs", record),
            request.schema_version,
        )
        .await?;
    }

    if !request.follow {
        write_response(writer, &Response::log_end("logs"), request.schema_version).await?;
        return Ok(true);
    }

    loop {
        if daemon.is_shutdown_requested() {
            return Ok(false);
        }
        match receiver.recv().await {
            Ok(record) => {
                if record.seq <= last_seq {
                    continue;
                }
                if Level::parse_name(&record.level) > level {
                    continue;
                }
                last_seq = record.seq;
                write_response(
                    writer,
                    &Response::record("logs", record),
                    request.schema_version,
                )
                .await?;
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::debug!(skipped, "log follower lagged; resuming at the next record");
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(false),
        }
    }
}

async fn write_response<W>(
    writer: &mut W,
    response: &Response,
    schema_version: u32,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut response = response.clone();
    response.schema_version = schema_version;
    let line = encode_line(&response).map_err(io::Error::other)?;
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await
}

#[cfg(unix)]
async fn platform_serve(daemon: Arc<Daemon>) -> AevanResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = endpoint_path()?;
    let system = is_system_endpoint(&path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let mut permissions = std::fs::metadata(parent)?.permissions();
        // The system directory must be traversable by the logged-in user; the
        // per-user directory stays private.
        permissions.set_mode(if system { 0o755 } else { 0o700 });
        std::fs::set_permissions(parent, permissions)?;
    }

    // A connect that succeeds means another daemon owns the socket. A failed
    // connect means a stale file from a killed process; remove it.
    if tokio::net::UnixStream::connect(&path).await.is_ok() {
        return Err(already_listening(&path.display().to_string()));
    }
    let _ = std::fs::remove_file(&path);

    let listener = tokio::net::UnixListener::bind(&path)?;
    let mut permissions = std::fs::metadata(&path)?.permissions();
    // A root daemon must accept the logged-in user's CLI and GUI. The socket
    // alone is world-writable; nothing else is widened.
    permissions.set_mode(if system { 0o666 } else { 0o600 });
    std::fs::set_permissions(&path, permissions)?;
    tracing::info!(endpoint = %path.display(), "aevand control socket listening");

    loop {
        if daemon.is_shutdown_requested() {
            break;
        }
        tokio::select! {
            biased;
            _ = daemon.wait_for_shutdown() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let daemon = daemon.clone();
                        tokio::spawn(async move {
                            handle_connection(stream, daemon).await;
                        });
                    }
                    Err(error) => tracing::warn!(%error, "control accept failed"),
                }
            }
        }
    }
    daemon.stop_connection().await;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[cfg(windows)]
async fn platform_serve(daemon: Arc<Daemon>) -> AevanResult<()> {
    use crate::pipe_security::{self, CreateError};

    // Resolve the interactive user SID up front. The daemon usually runs
    // elevated, so the default pipe descriptor would deny the normal CLI.
    let user_sid = pipe_security::current_user_sid().map_err(|error| {
        let error = pipe_security::refuse_default_descriptor(error);
        tracing::error!(%error, "cannot read the current user SID");
        error
    })?;

    let mut first = true;
    loop {
        let is_first = first;
        first = false;
        let server = match pipe_security::create_server(PIPE_NAME, is_first, &user_sid) {
            Ok(server) => server,
            Err(CreateError::Security(error)) => {
                let error = pipe_security::refuse_default_descriptor(error);
                tracing::error!(%error, "refusing to start the control pipe");
                return Err(error);
            }
            // ERROR_ACCESS_DENIED on the first instance means another process
            // already owns the fixed pipe name.
            Err(CreateError::Pipe(error)) if is_first && error.raw_os_error() == Some(5) => {
                let error = already_listening(PIPE_NAME);
                tracing::error!(endpoint = PIPE_NAME, "the control pipe is already owned");
                return Err(error);
            }
            Err(CreateError::Pipe(error)) => return Err(AevanError::Io(error)),
        };
        if daemon.is_shutdown_requested() {
            break;
        }
        tokio::select! {
            biased;
            _ = daemon.wait_for_shutdown() => break,
            result = server.connect() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "named pipe connect failed");
                    continue;
                }
                let daemon = daemon.clone();
                tokio::spawn(async move {
                    handle_connection(server, daemon).await;
                });
            }
        }
    }
    tracing::info!("aevand control pipe closed");
    daemon.stop_connection().await;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
async fn platform_serve(_daemon: Arc<Daemon>) -> AevanResult<()> {
    Err(AevanError::Unsupported(
        "no control endpoint implementation for this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::logs::LogHub;
    use crate::state::DaemonState;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "aevan-server-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn daemon(label: &str) -> Arc<Daemon> {
        let dir = TempDir::new(label);
        // Keep the directory alive for the test by leaking it; the OS cleans
        // the temp tree and the path is only used for the journal.
        let dir = Box::leak(Box::new(dir));
        Arc::new(Daemon::new(&dir.0, LogHub::new()))
    }

    async fn round_trip(daemon: Arc<Daemon>, requests: &[Request]) -> Vec<Response> {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let task = tokio::spawn(serve_connection(server, daemon));
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);

        for request in requests {
            let line = encode_line(request).expect("encode");
            write.write_all(line.as_bytes()).await.expect("write");
            write.flush().await.expect("flush");
        }

        let mut responses = Vec::new();
        for _ in requests {
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read");
            if line.is_empty() {
                break;
            }
            responses.push(serde_json::from_str(line.trim()).expect("response"));
        }
        task.abort();
        let _ = task.await;
        responses
    }

    #[tokio::test]
    async fn status_round_trips_over_an_in_memory_transport() {
        let responses = round_trip(daemon("status"), &[Request::status()]).await;
        assert_eq!(responses.len(), 1);
        let response = &responses[0];
        assert!(response.ok);
        assert_eq!(response.schema_version, crate::protocol::SCHEMA_VERSION);
        assert_eq!(response.command, "status");
        let status = response.status.as_ref().expect("status");
        assert_eq!(status.state, "disconnected");
        assert_eq!(status.route_count, 0);
        assert!(status.dns.is_empty());
    }

    #[tokio::test]
    async fn an_unknown_command_returns_a_typed_error() {
        let mut request = Request::status();
        request.command = "explode".into();
        let responses = round_trip(daemon("unknown"), &[request]).await;
        let response = &responses[0];
        assert!(!response.ok);
        assert_eq!(response.command, "explode");
        assert!(response.error.as_deref().unwrap_or("").contains("unknown"));
    }

    #[tokio::test]
    async fn an_unsupported_schema_is_rejected_with_exit_7() {
        let mut request = Request::status();
        request.schema_version = 99;
        let responses = round_trip(daemon("schema"), &[request]).await;
        let response = &responses[0];
        assert!(!response.ok);
        assert_eq!(response.exit_code, Some(7));
    }

    #[tokio::test]
    async fn logs_without_follow_returns_history_and_an_end_marker() {
        let daemon = daemon("logs");
        daemon.logs().record(Level::Info, "test", "hello".into());
        daemon.logs().record(Level::Debug, "test", "hidden".into());

        let (client, server) = tokio::io::duplex(16 * 1024);
        let task = tokio::spawn(serve_connection(server, daemon));
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);

        let line = encode_line(&Request::logs(false, Some("info".into()))).expect("encode");
        write.write_all(line.as_bytes()).await.expect("write");
        write.flush().await.expect("flush");

        let mut seen = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read");
            let response: Response = serde_json::from_str(line.trim()).expect("response");
            if response.done == Some(true) {
                break;
            }
            seen.push(response.record.expect("record"));
        }
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].message, "hello");
        assert_eq!(seen[0].level, "info");
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn shutdown_returns_a_response_and_stops_the_server() {
        let daemon = daemon("shutdown");
        let responses = round_trip(daemon.clone(), &[Request::shutdown()]).await;
        assert!(responses[0].ok);
        assert!(daemon.is_shutdown_requested());
        assert_eq!(daemon.snapshot().state, "disconnected");
    }

    #[tokio::test]
    async fn a_connect_without_a_password_is_a_typed_config_error() {
        let mut request = Request::connect(
            None,
            None,
            None,
            "example_user".into(),
            crate::protocol::SecretString::new(""),
            None,
        );
        request.password = None;
        let responses = round_trip(daemon("connect-missing"), &[request]).await;
        assert!(!responses[0].ok);
        assert_eq!(responses[0].exit_code, Some(1));
    }

    #[tokio::test]
    async fn a_version_one_connect_resolves_the_profile_from_the_store() {
        let dir = TempDir::new("v1-store");
        let path = dir.0.join("profiles.toml");
        let mut store = aevan_core::ProfileStore::default();
        store
            .upsert(
                aevan_core::Profile::new(
                    "example",
                    "https://vpn.example.net/example_realm",
                    "example_realm",
                )
                .expect("profile"),
            )
            .expect("upsert");
        store.save(&path).expect("save store");

        let daemon = Arc::new(Daemon::with_profile_store_path(
            &dir.0,
            LogHub::new(),
            Some(path),
        ));
        let mut request = Request::connect(
            Some("example".into()),
            None,
            None,
            "example_user".into(),
            crate::protocol::SecretString::new(""),
            None,
        );
        request.schema_version = 1;

        let responses = round_trip(daemon, &[request]).await;
        let response = &responses[0];
        assert!(!response.ok);
        assert_eq!(response.schema_version, 1);
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|error| error.contains("password must not be empty")),
            "the store lookup must have succeeded: {:?}",
            response.error
        );
    }

    #[tokio::test]
    async fn a_version_two_connect_ignores_an_unreadable_store() {
        // Point the fallback at a directory: loading it as a TOML file fails,
        // so reaching the password check proves the store was never read.
        let dir = TempDir::new("v2-store");
        let unreadable = dir.0.join("profiles.toml");
        std::fs::create_dir(&unreadable).expect("directory in place of a store");
        let daemon = Arc::new(Daemon::with_profile_store_path(
            &dir.0,
            LogHub::new(),
            Some(unreadable),
        ));

        let request = Request::connect(
            Some("missing".into()),
            Some("https://127.0.0.1:1/example_realm".into()),
            Some("example_realm".into()),
            "example_user".into(),
            crate::protocol::SecretString::new(""),
            None,
        );

        let responses = round_trip(daemon, &[request]).await;
        let response = &responses[0];
        assert!(!response.ok);
        assert_eq!(response.schema_version, 2);
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|error| error.contains("password must not be empty")),
            "the version-2 path must not consult the store: {:?}",
            response.error
        );
    }

    #[tokio::test]
    async fn a_connect_without_gateway_or_realm_uses_the_store_and_fails_typed() {
        let dir = TempDir::new("unknown-profile");
        let store = dir.0.join("profiles.toml");
        let daemon = Arc::new(Daemon::with_profile_store_path(
            &dir.0,
            LogHub::new(),
            Some(store),
        ));
        let request = Request::connect(
            Some("missing".into()),
            None,
            None,
            "example_user".into(),
            crate::protocol::SecretString::new("hunter2"),
            None,
        );

        let responses = round_trip(daemon, &[request]).await;
        let response = &responses[0];
        assert!(!response.ok);
        assert_eq!(response.exit_code, Some(1));
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|error| error.contains("profile 'missing' was not found")),
            "{:?}",
            response.error
        );
    }

    #[tokio::test]
    async fn status_reports_failed_reason_without_secrets() {
        let daemon = daemon("failed");
        daemon.mark_recovery_failed("journal recovery failed");
        assert_eq!(daemon.snapshot().state, "failed");
        let responses = round_trip(daemon, &[Request::status()]).await;
        let status = responses[0].status.as_ref().expect("status");
        assert_eq!(status.state, "failed");
        assert_eq!(status.reason.as_deref(), Some("journal recovery failed"));
        assert_eq!(DaemonState::Failed { reason: "x".into() }.name(), "failed");
    }

    #[tokio::test]
    async fn recover_reports_counts_and_clears_a_missing_journal() {
        let daemon = daemon("recover-clean");
        let responses = round_trip(daemon.clone(), &[Request::recover()]).await;
        let response = &responses[0];
        assert!(response.ok);
        assert_eq!(response.command, "recover");
        let report = response.recovery.as_ref().expect("recovery counts");
        assert_eq!(report.rolled_back, 0);
        assert_eq!(report.skipped_absent, 0);
        assert_eq!(report.failed(), 0);
        assert_eq!(daemon.snapshot().state, "disconnected");
    }

    #[tokio::test]
    async fn recovery_incomplete_is_its_own_status_state() {
        let dir = TempDir::new("recover-incomplete");
        std::fs::write(crate::journal::journal_path(&dir.0), b"{}").expect("journal");
        let daemon = Arc::new(Daemon::new(&dir.0, LogHub::new()));
        daemon.mark_recovery_incomplete(crate::protocol::RecoveryReport {
            rolled_back: 2,
            skipped_absent: 0,
            failures: vec![crate::protocol::RecoveryFailure {
                step: "route".into(),
                reason: "denied".into(),
            }],
            removed: false,
            journal: Some("aevand.journal".into()),
        });
        let responses = round_trip(daemon.clone(), &[Request::status()]).await;
        let status = responses[0].status.as_ref().expect("status");
        assert_eq!(status.state, "recovery-incomplete");
        let report = status.recovery.as_ref().expect("recovery");
        assert_eq!(report.rolled_back, 2);
        assert_eq!(report.failed(), 1);
        assert!(status.reason.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn the_system_endpoint_is_tried_before_the_per_user_endpoint() {
        let system = PathBuf::from("/Library/Application Support/Aevan/aevan.sock");
        let per_user = PathBuf::from("/Users/example/Library/Application Support/aevan/aevan.sock");
        assert_eq!(
            ordered_candidates_optional(Some(system.clone()), Some(per_user.clone()))
                .expect("both endpoints"),
            vec![system, per_user]
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_system_endpoint_is_listed_once() {
        let system = PathBuf::from("/Library/Application Support/Aevan/aevan.sock");
        assert_eq!(
            ordered_candidates_optional(Some(system.clone()), Some(system.clone()))
                .expect("both endpoints"),
            vec![system]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_root_daemon_binds_system_and_other_users_bind_per_user() {
        let system = PathBuf::from("/Library/Application Support/Aevan/aevan.sock");
        let per_user = PathBuf::from("/Users/example/Library/Application Support/aevan/aevan.sock");
        assert_eq!(
            select_binding_endpoint(true, Some(system.clone()), per_user.clone()),
            system
        );
        assert_eq!(
            select_binding_endpoint(false, Some(system), per_user.clone()),
            per_user
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unknown_uid_without_a_system_endpoint_keeps_the_per_user_endpoint() {
        let per_user = PathBuf::from("/Users/example/.config/aevan/aevan.sock");
        assert_eq!(
            select_binding_endpoint(true, None, per_user.clone()),
            per_user
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_root_daemon_binds_without_a_resolvable_home() {
        // launchd starts system daemons with no HOME. The binding endpoint must
        // still resolve, or aevand exits 1 before it opens the socket.
        let system = system_endpoint_path().expect("unix has a system endpoint here");
        assert_eq!(endpoint_path_for_root(true).expect("root resolves"), system);
    }

    #[cfg(unix)]
    #[test]
    fn candidates_survive_a_missing_per_user_endpoint() {
        let system = PathBuf::from("/run/aevan/aevan.sock");
        let only_system = ordered_candidates_optional(Some(system.clone()), None)
            .expect("the system endpoint alone is enough");
        assert_eq!(only_system, vec![system]);

        let only_user =
            ordered_candidates_optional(None, Some(PathBuf::from("/home/u/aevan.sock")))
                .expect("the per-user endpoint alone is enough");
        assert_eq!(only_user.len(), 1);

        assert!(ordered_candidates_optional(None, None).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_system_endpoint_matches_the_documented_path() {
        assert_eq!(
            system_endpoint_path().as_deref(),
            Some(std::path::Path::new(
                "/Library/Application Support/Aevan/aevan.sock"
            ))
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn the_linux_system_endpoint_matches_the_documented_path() {
        assert_eq!(
            system_endpoint_path().as_deref(),
            Some(std::path::Path::new("/run/aevan/aevan.sock"))
        );
    }
}
