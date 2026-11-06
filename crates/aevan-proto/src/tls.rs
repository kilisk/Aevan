//! TLS handshake plus one credential-free HTTP request.
//!
//! `aevan doctor` uses [`inspect_https`] to report the certificate chain the
//! gateway presents and whether the login page advertises a `realm` field. No
//! credential of any kind is read or sent.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Serialize;
use x509_parser::parse_x509_certificate;
use x509_parser::time::ASN1Time;

use crate::error::ProtoError;
use crate::http::{build_get_request, parse_response, HttpResponse};
use crate::url::Url;

/// Hard cap on the HTTP response read by the doctor probe.
pub const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

/// Fields extracted from one certificate in the presented chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertInfo {
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// `notBefore` in human-readable form.
    pub not_before: String,
    /// `notAfter` in human-readable form.
    pub not_after: String,
}

/// TLS facts observed during the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsObservation {
    /// Negotiated protocol version, for example `TLSv1_3`.
    pub protocol: String,
    /// Presented chain, leaf first.
    pub chain: Vec<CertInfo>,
}

/// TLS and HTTP observations from one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// Handshake facts.
    pub tls: TlsObservation,
    /// Response to the credential-free `GET`.
    pub http: HttpResponse,
}

/// A raw TLS byte stream for protocols that switch away from HTTP mid-connection.
///
/// Network Connect performs an HTTP request and then keeps the same TLS
/// connection for binary oNCP framing. [`RawTls`] exposes the byte stream
/// without imposing HTTP semantics. It uses exactly the same [`tls_config`]
/// and webpki roots as the redirect-following client, so it introduces no new
/// trust decision.
pub struct RawTls {
    stream: StreamOwned<ClientConnection, TcpStream>,
}

impl RawTls {
    /// Connect and complete the TLS handshake with the URL host.
    ///
    /// The socket read and write timeouts are set from `timeout`.
    pub fn connect(url: &Url, timeout: Duration) -> Result<Self, ProtoError> {
        let (connection, socket) = connect(url, timeout)?;
        Ok(Self {
            stream: StreamOwned::new(connection, socket),
        })
    }

    /// Write every byte and flush the TLS stream.
    pub fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes)?;
        self.stream.flush()
    }

    /// Read exactly `buffer.len()` bytes.
    pub fn read_exact(&mut self, buffer: &mut [u8]) -> std::io::Result<()> {
        self.stream.read_exact(buffer)
    }

    /// Read up to `buffer.len()` bytes, returning the count read.
    pub fn read_some(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buffer)
    }

    /// Change the socket read timeout for the rest of this session.
    pub fn set_read_timeout(&mut self, timeout: Duration) -> std::io::Result<()> {
        self.stream.sock.set_read_timeout(Some(timeout))
    }

    /// The connected peer's address.
    ///
    /// Network Connect sends ESP to this address, not to the internal tunnel
    /// gateway in the KMP 301 configuration.
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.sock.peer_addr()
    }
}

impl std::fmt::Debug for RawTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawTls").finish_non_exhaustive()
    }
}

/// Connect over TLS, inspect the chain, and perform one HTTP `GET`.
///
/// The socket has read/write timeouts so a stuck gateway cannot hang the CLI.
pub fn inspect_https(url: &Url, timeout: Duration) -> Result<Inspection, ProtoError> {
    let (connection, socket) = connect(url, timeout)?;
    let tls = observe(&connection)?;

    let mut stream = StreamOwned::new(connection, socket);
    stream
        .write_all(build_get_request(url).as_bytes())
        .map_err(ProtoError::Io)?;
    stream.flush().map_err(ProtoError::Io)?;

    let mut raw = Vec::new();
    let mut limited = stream.take(MAX_RESPONSE_BYTES);
    let read_error = limited.read_to_end(&mut raw).err();
    if raw.len() as u64 >= MAX_RESPONSE_BYTES {
        return Err(ProtoError::Http(format!(
            "response exceeds the {MAX_RESPONSE_BYTES}-byte doctor limit"
        )));
    }

    // Many HTTP/1.x servers close the socket without a TLS close_notify. If a
    // complete response arrived, that abrupt shutdown is not a probe failure.
    match parse_response(&raw) {
        Ok(http) => Ok(Inspection { tls, http }),
        Err(parse_error) => match read_error {
            Some(error) => Err(ProtoError::Io(error)),
            None => Err(parse_error),
        },
    }
}

pub(crate) fn tls_config() -> Result<Arc<ClientConfig>, ProtoError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| ProtoError::Tls(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub(crate) fn connect(
    url: &Url,
    timeout: Duration,
) -> Result<(ClientConnection, TcpStream), ProtoError> {
    if !url.is_https() {
        return Err(ProtoError::InvalidUrl("TLS requires an https URL".into()));
    }

    let config = tls_config()?;
    let server_name = ServerName::try_from(url.host.clone())
        .map_err(|_| ProtoError::InvalidUrl(format!("invalid TLS server name '{}'", url.host)))?;

    // Connect with an explicit per-address timeout. `TcpStream::connect` uses
    // the OS default (about 21s per address on Windows) and gives no way to
    // bound the attempt, which made a stalled SYN look like a dead gateway
    // while the same host answered other requests immediately.
    let addresses: Vec<std::net::SocketAddr> = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(ProtoError::Io)?
        .collect();
    if addresses.is_empty() {
        return Err(ProtoError::InvalidUrl(format!(
            "no address for '{}'",
            url.host
        )));
    }

    let mut socket = None;
    let mut last_error = None;
    let connect_timeout = timeout.min(Duration::from_secs(10));
    for address in &addresses {
        match TcpStream::connect_timeout(address, connect_timeout) {
            Ok(stream) => {
                socket = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut socket = socket.ok_or_else(|| {
        ProtoError::Io(last_error.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "connect failed")
        }))
    })?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    let _ = socket.set_nodelay(true);

    let mut connection = ClientConnection::new(config, server_name)
        .map_err(|error| ProtoError::Tls(error.to_string()))?;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|error| ProtoError::Tls(error.to_string()))?;
    }

    Ok((connection, socket))
}

pub(crate) fn observe(connection: &ClientConnection) -> Result<TlsObservation, ProtoError> {
    let protocol = connection
        .protocol_version()
        .map(|version| format!("{version:?}"))
        .unwrap_or_else(|| "unknown".to_owned());

    let certificates = connection
        .peer_certificates()
        .ok_or_else(|| ProtoError::Certificate("server presented no certificate".into()))?;
    if certificates.is_empty() {
        return Err(ProtoError::Certificate("empty certificate chain".into()));
    }

    let mut chain = Vec::with_capacity(certificates.len());
    for certificate in certificates {
        chain.push(parse_certificate(certificate.as_ref())?);
    }

    Ok(TlsObservation { protocol, chain })
}

fn parse_certificate(der: &[u8]) -> Result<CertInfo, ProtoError> {
    let (_, certificate) =
        parse_x509_certificate(der).map_err(|error| ProtoError::Certificate(format!("{error}")))?;
    let validity = certificate.validity();

    Ok(CertInfo {
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        not_before: time_string(&validity.not_before),
        not_after: time_string(&validity.not_after),
    })
}

fn time_string(time: &ASN1Time) -> String {
    time.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn rejects_non_https_urls_before_connecting() {
        let url = Url {
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: 1,
            path_and_query: "/".into(),
        };
        let error = inspect_https(&url, Duration::from_millis(1)).expect_err("must reject");
        assert!(matches!(error, ProtoError::InvalidUrl(_)));
    }

    #[test]
    fn unparsable_der_is_reported_as_a_certificate_error() {
        let error = parse_certificate(&[0x30, 0x00]).expect_err("must fail");
        assert!(matches!(error, ProtoError::Certificate(_)));
    }

    #[test]
    fn ip_server_names_are_accepted() {
        let name = ServerName::try_from(IpAddr::from([127, 0, 0, 1]).to_string());
        assert!(name.is_ok());
    }
}
