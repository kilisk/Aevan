//! Protocol-layer errors.
//!
//! Messages may contain host names and status codes, never credentials: this
//! layer does not receive them at M0 and must not echo them when it does.

/// Errors from URL parsing, TLS or HTTP.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// The URL is malformed or uses an unsupported scheme.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    /// The TLS handshake or protocol failed.
    #[error("TLS failure: {0}")]
    Tls(String),
    /// The presented certificate chain could not be parsed.
    #[error("certificate error: {0}")]
    Certificate(String),
    /// The HTTP response was malformed or truncated.
    #[error("HTTP error: {0}")]
    Http(String),
    /// Socket I/O failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
