//! Blocking control client for the CLI.
//!
//! `aevan` stays a synchronous command: each call builds a small current-thread
//! Tokio runtime, connects to the endpoint and performs the JSON-line exchange.
//! Only `logs --follow` keeps a stream open.

use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use aevan_core::AevanError;

use crate::protocol::{encode_line, Request, Response};
use crate::server;

/// Why a control connection could not be established.
///
/// Kept separate from [`ClientError`] so the three operator-facing conditions
/// can be classified and tested without a live pipe or Windows API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachFailure {
    /// No daemon is listening at the endpoint.
    NoDaemon,
    /// The endpoint exists but this process may not open it (Windows error 5).
    AccessDenied,
    /// Something answered with a protocol version this build does not know.
    ProtocolMismatch,
}

impl ReachFailure {
    /// Classify an OS error raised while opening the control endpoint.
    ///
    /// Returns `None` for a transport error that is not one of the three
    /// reachability conditions.
    pub fn from_connect_error(error: &io::Error) -> Option<Self> {
        if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(5) {
            return Some(Self::AccessDenied);
        }
        let unavailable = matches!(
            error.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ) || matches!(error.raw_os_error(), Some(2) | Some(3) | Some(53));
        unavailable.then_some(Self::NoDaemon)
    }

    fn client_error(self, endpoint: &str) -> ClientError {
        let message = self.message(endpoint);
        match self {
            Self::NoDaemon => ClientError::Unavailable(message),
            Self::AccessDenied => ClientError::AccessDenied(message),
            Self::ProtocolMismatch => ClientError::ProtocolMismatch(message),
        }
    }

    /// The operator-facing message for this failure.
    pub fn message(self, endpoint: &str) -> String {
        match self {
            Self::NoDaemon => format!(
                "cannot reach the aevan daemon on {endpoint}: no daemon is listening — start aevand first"
            ),
            Self::AccessDenied => format!(
                "cannot reach the aevan daemon on {endpoint}: access denied — run aevand and aevan at the same elevation, or start aevand first"
            ),
            Self::ProtocolMismatch => format!(
                "cannot reach the aevan daemon on {endpoint}: protocol mismatch — stop aevand and restart it with the same version as aevan"
            ),
        }
    }

    /// Map this condition into the public error taxonomy.
    ///
    /// Access denied is a privilege failure (exit 6), not a gateway/network
    /// failure. A protocol mismatch is unsupported (exit 7).
    pub fn into_aevan(self, endpoint: &str) -> AevanError {
        match self {
            Self::NoDaemon => AevanError::Network(self.message(endpoint)),
            Self::AccessDenied => AevanError::Privilege(self.message(endpoint)),
            Self::ProtocolMismatch => AevanError::Unsupported(self.message(endpoint)),
        }
    }
}

/// Failure to reach or understand the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// No daemon is listening at the endpoint.
    Unavailable(String),
    /// The endpoint exists but access was denied (Windows error 5).
    AccessDenied(String),
    /// The daemon does not speak this build's protocol version.
    ProtocolMismatch(String),
    /// The endpoint exists but the exchange failed.
    Transport(String),
    /// The daemon sent a malformed response.
    Protocol(String),
}

impl ClientError {
    /// Whether the failure means "no daemon is running".
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    /// Map into the public error taxonomy.
    ///
    /// A missing daemon is a control-transport failure, so it maps to exit 4.
    /// Access denied maps to privilege (exit 6). A protocol mismatch maps to
    /// unsupported (exit 7). A malformed answer is genuinely internal (exit 1).
    pub fn into_aevan(self) -> AevanError {
        match self {
            Self::Unavailable(message) | Self::Transport(message) => AevanError::Network(message),
            Self::AccessDenied(message) => AevanError::Privilege(message),
            Self::ProtocolMismatch(message) => AevanError::Unsupported(message),
            Self::Protocol(message) => AevanError::Io(io::Error::other(message)),
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message)
            | Self::AccessDenied(message)
            | Self::ProtocolMismatch(message)
            | Self::Transport(message)
            | Self::Protocol(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ClientError {}

fn runtime() -> Result<tokio::runtime::Runtime, ClientError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| ClientError::Transport(error.to_string()))
}

/// Send one request and read one response.
pub fn request(request: &Request, read_timeout: Option<Duration>) -> Result<Response, ClientError> {
    let runtime = runtime()?;
    runtime.block_on(async move {
        let stream = connect_stream().await.map_err(map_connect)?;
        exchange(stream, request, read_timeout).await
    })
}

async fn exchange<S>(
    stream: S,
    request: &Request,
    read_timeout: Option<Duration>,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read, mut write) = tokio::io::split(stream);
    let line = encode_line(request).map_err(|error| ClientError::Protocol(error.to_string()))?;
    write
        .write_all(line.as_bytes())
        .await
        .map_err(|error| ClientError::Transport(error.to_string()))?;
    write
        .flush()
        .await
        .map_err(|error| ClientError::Transport(error.to_string()))?;

    let mut reader = BufReader::new(read);
    let mut response_line = String::new();
    let read_line = reader.read_line(&mut response_line);
    let read = match read_timeout {
        Some(limit) => timeout(limit, read_line)
            .await
            .map_err(|_| ClientError::Transport("the daemon did not answer in time".into()))?,
        None => read_line.await,
    }
    .map_err(|error| ClientError::Transport(error.to_string()))?;
    if read == 0 {
        return Err(ClientError::Protocol(
            "the daemon closed the connection without a response".into(),
        ));
    }
    parse_response(&response_line, &server::endpoint_description())
}

fn parse_response(line: &str, endpoint: &str) -> Result<Response, ClientError> {
    let response: Response = serde_json::from_str(line.trim())
        .map_err(|error| ClientError::Protocol(format!("invalid daemon response: {error}")))?;
    if response.schema_version != crate::protocol::SCHEMA_VERSION {
        return Err(ReachFailure::ProtocolMismatch.client_error(endpoint));
    }
    Ok(response)
}

/// Stream responses for `logs`.
pub fn stream_logs<F>(request: &Request, mut on_response: F) -> Result<(), ClientError>
where
    F: FnMut(Response) -> bool,
{
    let runtime = runtime()?;
    runtime.block_on(async move {
        let stream = connect_stream().await.map_err(map_connect)?;
        let (read, mut write) = tokio::io::split(stream);
        let line =
            encode_line(request).map_err(|error| ClientError::Protocol(error.to_string()))?;
        write
            .write_all(line.as_bytes())
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        write
            .flush()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;

        let mut reader = BufReader::new(read);
        let endpoint = server::endpoint_description();
        loop {
            let mut response_line = String::new();
            let read = reader
                .read_line(&mut response_line)
                .await
                .map_err(|error| ClientError::Transport(error.to_string()))?;
            if read == 0 {
                return Ok(());
            }
            let response = parse_response(&response_line, &endpoint)?;
            if !on_response(response) {
                return Ok(());
            }
        }
    })
}

fn map_connect(error: io::Error) -> ClientError {
    match ReachFailure::from_connect_error(&error) {
        Some(failure) => failure.client_error(&server::endpoint_description()),
        None => ClientError::Transport(error.to_string()),
    }
}

/// The `aevand` binary beside the current executable, when present.
pub fn daemon_binary_beside_executable() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let name = if cfg!(windows) {
        "aevand.exe"
    } else {
        "aevand"
    };
    let candidate = executable.parent()?.join(name);
    candidate.is_file().then_some(candidate)
}

/// Start the sibling daemon in the background.
///
/// No credentials are passed: the daemon is only a listener until a control
/// request arrives.
pub fn start_daemon() -> Result<PathBuf, ClientError> {
    let executable = daemon_binary_beside_executable().ok_or_else(|| {
        ClientError::Unavailable(format!(
            "the aevan daemon is not running and aevand was not found beside {}",
            std::env::current_exe()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| "the executable".to_owned())
        ))
    })?;

    std::process::Command::new(&executable)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| {
            ClientError::Transport(format!("could not start {}: {error}", executable.display()))
        })?;
    Ok(executable)
}

/// Wait until the control endpoint answers a status request.
pub fn wait_for_daemon(limit: Duration) -> Result<(), ClientError> {
    let start = Instant::now();
    loop {
        match request(&Request::status(), Some(Duration::from_millis(750))) {
            Ok(_) => return Ok(()),
            Err(error) if error.is_unavailable() && start.elapsed() < limit => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
async fn connect_stream() -> io::Result<tokio::net::UnixStream> {
    let path = server::endpoint_path().map_err(io::Error::other)?;
    tokio::net::UnixStream::connect(path).await
}

#[cfg(windows)]
async fn connect_stream() -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(server::PIPE_NAME)
}

#[cfg(not(any(unix, windows)))]
async fn connect_stream() -> io::Result<tokio::io::DuplexStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no control endpoint on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SCHEMA_VERSION;

    const ENDPOINT: &str = r"\\.\pipe\aevan";

    #[test]
    fn malformed_responses_are_protocol_errors() {
        let error = parse_response("not json", ENDPOINT).expect_err("must fail");
        assert!(matches!(error, ClientError::Protocol(_)));
        assert_eq!(error.into_aevan().exit_code(), 1);
    }

    #[test]
    fn responses_parse_with_the_schema_version() {
        let line =
            format!("{{\"schema_version\":{SCHEMA_VERSION},\"ok\":true,\"command\":\"status\"}}\n");
        let response = parse_response(&line, ENDPOINT).expect("response");
        assert!(response.ok);
        assert_eq!(response.command, "status");
    }

    #[test]
    fn every_reach_failure_has_a_named_daemon_and_the_right_code() {
        let cases = [
            (ReachFailure::NoDaemon, 4, "no daemon is listening"),
            (ReachFailure::AccessDenied, 6, "access denied"),
            (ReachFailure::ProtocolMismatch, 7, "protocol mismatch"),
        ];
        for (failure, code, phrase) in cases {
            let error = failure.into_aevan(ENDPOINT);
            let message = error.to_string();
            assert_eq!(error.exit_code(), code, "{message}");
            assert!(message.contains(ENDPOINT), "{message}");
            assert!(message.contains(phrase), "{message}");
        }
    }

    #[test]
    fn connect_errors_are_classified_as_no_daemon_or_access_denied() {
        let not_found = io::Error::from_raw_os_error(2);
        assert_eq!(
            ReachFailure::from_connect_error(&not_found),
            Some(ReachFailure::NoDaemon)
        );

        let access_denied = io::Error::from_raw_os_error(5);
        assert_eq!(
            ReachFailure::from_connect_error(&access_denied),
            Some(ReachFailure::AccessDenied)
        );

        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(
            ReachFailure::from_connect_error(&refused),
            Some(ReachFailure::NoDaemon)
        );

        let other = io::Error::from(io::ErrorKind::TimedOut);
        assert_eq!(ReachFailure::from_connect_error(&other), None);
    }

    #[test]
    fn a_different_schema_is_a_protocol_mismatch() {
        let line = format!(
            "{{\"schema_version\":{},\"ok\":true,\"command\":\"status\"}}\n",
            SCHEMA_VERSION + 1
        );
        let error = parse_response(&line, ENDPOINT).expect_err("must fail");
        assert!(matches!(error, ClientError::ProtocolMismatch(_)));
        assert_eq!(error.into_aevan().exit_code(), 7);
    }

    #[test]
    fn unavailable_maps_to_exit_4_access_denied_to_6_and_protocol_to_exit_1() {
        assert_eq!(
            ClientError::Unavailable("gone".into())
                .into_aevan()
                .exit_code(),
            4
        );
        assert_eq!(
            ClientError::Transport("broken".into())
                .into_aevan()
                .exit_code(),
            4
        );
        assert_eq!(
            ClientError::AccessDenied("denied".into())
                .into_aevan()
                .exit_code(),
            6
        );
        assert_eq!(
            ClientError::ProtocolMismatch("version".into())
                .into_aevan()
                .exit_code(),
            7
        );
        assert_eq!(
            ClientError::Protocol("bad".into()).into_aevan().exit_code(),
            1
        );
    }
}
