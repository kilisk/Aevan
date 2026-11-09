//! Minimal HTTP/1.1 request building and response parsing.
//!
//! This is not a general HTTP client. It exists so `aevan doctor` can perform a
//! single credential-free `GET` over TLS. M1 adds cookie handling and form
//! scraping on top of it.

use std::fmt;

use crate::error::ProtoError;
use crate::url::Url;

/// A parsed HTTP response.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Numeric status code.
    pub status_code: u16,
    /// Reason phrase (possibly empty).
    pub reason: String,
    /// Header name/value pairs in wire order.
    pub headers: Vec<(String, String)>,
    /// Decoded body bytes (chunked transfer encoding removed).
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status_code", &self.status_code)
            .field("reason", &self.reason)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl HttpResponse {
    /// Look up a header case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value of a repeated header, in wire order.
    pub fn header_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether this response is a redirect with a `Location` header.
    pub fn is_redirect(&self) -> bool {
        matches!(self.status_code, 301 | 302 | 303 | 307 | 308) && self.header("location").is_some()
    }

    /// `Location` header, if present.
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    /// Body as lossy UTF-8.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Whether the HTML contains a `realm` form field.
    ///
    /// Accepts the common attribute spellings emitted by the gateway login page
    /// (`name="realm"`, `name='realm'`, unquoted, or an `id`).
    pub fn has_realm_field(&self) -> bool {
        let text = self.body_text().to_ascii_lowercase();
        [
            "name=\"realm\"",
            "name='realm'",
            "name=realm",
            "id=\"realm\"",
            "id='realm'",
        ]
        .iter()
        .any(|needle| text.contains(needle))
    }
}

/// A request ready to be written to a connection.
///
/// `Debug` intentionally omits header values and the body: request headers can
/// contain `Cookie` and the body can contain a password or token.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: String,
    /// Absolute target URL.
    pub url: Url,
    /// Additional headers. The builder adds the standard ones.
    pub headers: Vec<(String, String)>,
    /// Request body (empty for `GET`).
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url.to_string())
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl HttpRequest {
    /// A `GET` request with no extra headers.
    pub fn get(url: Url) -> Self {
        Self {
            method: "GET".to_owned(),
            url,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A form `POST` request.
    pub fn post(url: Url, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            method: "POST".to_owned(),
            url,
            headers: vec![("Content-Type".to_owned(), content_type.to_owned())],
            body,
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Encode the request as HTTP/1.1 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut head = String::new();
        head.push_str(&format!(
            "{} {} HTTP/1.1\r\n",
            self.method, self.url.path_and_query
        ));
        head.push_str(&format!("Host: {}\r\n", self.url.host_header()));
        head.push_str(&format!(
            "User-Agent: aevan/{}\r\n",
            env!("CARGO_PKG_VERSION")
        ));
        head.push_str("Accept: text/html,application/xhtml+xml\r\n");
        head.push_str("Accept-Encoding: identity\r\n");
        head.push_str("Connection: close\r\n");

        for (name, value) in &self.headers {
            validate_header(name, value)?;
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if !self.body.is_empty() {
            head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        head.push_str("\r\n");

        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }
}

fn validate_header(name: &str, value: &str) -> Result<(), ProtoError> {
    if name.is_empty()
        || name
            .bytes()
            .any(|byte| byte <= 0x20 || byte >= 0x7f || byte == b':')
        || value.bytes().any(|byte| byte == b'\r' || byte == b'\n')
    {
        return Err(ProtoError::Http("invalid request header".into()));
    }
    Ok(())
}

/// Build a single credential-free `GET`.
pub fn build_get_request(url: &Url) -> String {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: aevan-doctor/{}\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        url.path_and_query,
        url.host_header(),
        env!("CARGO_PKG_VERSION")
    )
}

/// Build a form `POST` with the standard headers.
pub fn build_post_request(
    url: &Url,
    content_type: &str,
    body: &[u8],
) -> Result<Vec<u8>, ProtoError> {
    HttpRequest::post(url.clone(), content_type, body.to_vec()).encode()
}

/// Parse an HTTP/1.x response from raw bytes.
pub fn parse_response(raw: &[u8]) -> Result<HttpResponse, ProtoError> {
    let header_end = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| ProtoError::Http("missing header terminator".into()))?;
    let header_bytes = &raw[..header_end];
    let body_bytes = &raw[header_end + 4..];

    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| ProtoError::Http("headers are not valid UTF-8".into()))?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ProtoError::Http("missing status line".into()))?;

    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(ProtoError::Http(format!(
            "unsupported status line '{status_line}'"
        )));
    }
    let status_code = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| ProtoError::Http(format!("invalid status line '{status_line}'")))?;
    let reason = parts.next().unwrap_or_default().to_owned();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ProtoError::Http(format!("malformed header '{line}'")))?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked {
        decode_chunked(body_bytes)?
    } else {
        body_bytes.to_vec()
    };

    Ok(HttpResponse {
        status_code,
        reason,
        headers,
        body,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let mut output = Vec::new();
    let mut position = 0;

    loop {
        let line_end = position
            + find_subslice(&input[position..], b"\r\n")
                .ok_or_else(|| ProtoError::Http("truncated chunk size".into()))?;
        let size_line = std::str::from_utf8(&input[position..line_end])
            .map_err(|_| ProtoError::Http("chunk size is not ASCII".into()))?;
        let size_text = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| ProtoError::Http(format!("invalid chunk size '{size_text}'")))?;
        position = line_end + 2;

        if size == 0 {
            break;
        }
        if position + size > input.len() {
            return Err(ProtoError::Http("truncated chunk body".into()));
        }
        output.extend_from_slice(&input[position..position + size]);
        position += size;

        if input.get(position..position + 2) != Some(b"\r\n") {
            return Err(ProtoError::Http("missing chunk terminator".into()));
        }
        position += 2;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello";

    #[test]
    fn parses_status_and_headers() {
        let response = parse_response(SIMPLE).expect("parse");
        assert_eq!(response.status_code, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(response.header("content-type"), Some("text/html"));
        assert_eq!(response.body_text(), "hello");
    }

    #[test]
    fn parses_empty_reason_phrase() {
        let raw = b"HTTP/1.1 302\r\nLocation: /next\r\n\r\n";
        let response = parse_response(raw).expect("parse");
        assert_eq!(response.status_code, 302);
        assert_eq!(response.reason, "");
        assert_eq!(response.header("Location"), Some("/next"));
    }

    #[test]
    fn decodes_chunked_bodies() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let response = parse_response(raw).expect("parse");
        assert_eq!(response.body_text(), "hello world");
    }

    #[test]
    fn detects_realm_in_common_spellings() {
        for body in [
            "<input type=\"hidden\" name=\"realm\" value=\"example_realm\">",
            "<input name='realm' value='x'>",
            "<input name=realm value=x>",
            "<form id=\"realm\">",
        ] {
            let raw = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
            let response = parse_response(raw.as_bytes()).expect("parse");
            assert!(response.has_realm_field(), "must detect {body}");
        }
    }

    #[test]
    fn does_not_invent_a_realm() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n<input name=\"username\">";
        let response = parse_response(raw).expect("parse");
        assert!(!response.has_realm_field());
    }

    #[test]
    fn rejects_malformed_responses() {
        assert!(parse_response(b"nonsense").is_err());
        assert!(parse_response(b"HTTP/1.1 abc OK\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nbroken\r\n\r\n").is_err());
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").is_err()
        );
    }

    #[test]
    fn request_is_credential_free_and_well_formed() {
        let url = Url::parse("https://vpn.example.net/example_realm").expect("url");
        let request = build_get_request(&url);
        assert!(request.starts_with("GET /example_realm HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: vpn.example.net\r\n"));
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
        assert!(!request.to_ascii_lowercase().contains("cookie:"));
        assert!(request.ends_with("\r\n\r\n"));
    }
}
