//! Redacted handshake dump for offline analysis.
//!
//! The dump is deliberately lossy about secrets. Cookie values, session ids
//! and ESP key material are removed before anything is serialised or written.
//! Every file is created owner-only where the platform supports it.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use aevan_core::redact::{is_sensitive_key, Redactor, REDACTED};
use aevan_core::{AevanError, AevanResult};
use aevan_nc::{ContinuationObservation, HandshakeOutcome, NcpConfig};
use aevan_proto::{parse_forms, CookieDiagnostics, HttpResponse, RedirectHop};

use crate::probe::{ProbeObservation, ProbeResponseObservation};

/// Key-block marker signature inside a KMP TLV: group attr 2, length 0x40.
const KEY_BLOCK_SIGNATURE: [u8; 6] = [0x00, 0x02, 0x00, 0x00, 0x00, 0x40];
/// Length of the ESP key block carried by KMP group 7 attr 2.
const KEY_BLOCK_LEN: usize = 0x40;
/// Maximum probe body bytes retained as hex and printable text.
const PROBE_BODY_PREFIX: usize = 256;

/// One redirect hop with any session-bearing query values redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HopDump {
    /// Requested URL.
    pub url: String,
    /// Response status.
    pub status_code: u16,
    /// Response reason.
    pub reason: String,
    /// Raw `Location` header, redacted.
    pub location: Option<String>,
}

/// One header with sensitive values replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderDump {
    /// Header name.
    pub name: String,
    /// Header value, or `[REDACTED]`.
    pub value: String,
}

/// One probe response with a bounded, redacted body preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeResponseDump {
    /// HTTP status, absent when no response arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// HTTP reason phrase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `Content-Type` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// `Content-Length` header parsed as a number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    /// Redirect `Location`, with every query value redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// First [`PROBE_BODY_PREFIX`] bytes as hex, with key blocks and cookie
    /// values replaced by markers.
    pub body_hex_prefix: String,
    /// First bytes as lossy text when the body is mostly printable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_text_prefix: Option<String>,
    /// Cookie metadata for the request, never values.
    pub cookies: CookieDiagnostics,
    /// Attempt-level failure, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One executed endpoint probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeDump {
    /// Stable short probe id.
    pub id: String,
    /// HTTP method.
    pub method: String,
    /// Request URL, with every query value redacted.
    pub url: String,
    /// Cookie metadata for the request, never values.
    pub cookies: CookieDiagnostics,
    /// The first response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ProbeResponseDump>,
    /// The single redirect target that was followed, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<ProbeResponseDump>,
    /// Request-level failure, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether the body carried NC configuration keys without a KMP 301.
    pub config_keys: bool,
}

/// The final login response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoginDump {
    /// HTTP status.
    pub status_code: u16,
    /// Reason phrase.
    pub reason: String,
    /// Headers with `Set-Cookie` redacted.
    pub headers: Vec<HeaderDump>,
    /// Whether the secondary token was submitted.
    pub token_submitted: bool,
    /// Credential POST field names in wire order, never their values.
    pub body_fields: Vec<String>,
}

/// One KMP record's framing only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrameDump {
    /// KMP message number when the record starts with a KMP header.
    pub message_number: Option<u16>,
    /// Declared record length, excluding the two-byte prefix.
    pub declared_length: usize,
    /// Body length actually read.
    pub body_length: usize,
}

/// One handshake attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttemptDump {
    /// `actual` or `fixed256`.
    pub content_length_variant: &'static str,
    /// HTTP status of the oNCP request.
    pub http_status: Option<u16>,
    /// HTTP response headers, redacted.
    pub http_headers: Vec<HeaderDump>,
    /// The gateway's binary status byte.
    pub status_byte: Option<u8>,
    /// Each KMP record's framing facts.
    pub frames: Vec<FrameDump>,
    /// Hex of the request with `Cookie` redacted.
    pub request_hex: String,
    /// Hex of the response with any ESP key block replaced by a marker.
    pub response_hex: String,
    /// Number of raw response bytes received before the attempt ended.
    pub bytes_received: usize,
    /// Read-failure offset in the raw response, lowercase hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_offset_hex: Option<String>,
    /// Whether the attempt ended on a transport read or write error.
    pub transport_error: bool,
    /// Why this attempt failed, if it did.
    pub error: Option<String>,
}

/// The handshake portion of the dump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HandshakeDump {
    /// The content-length variant that produced KMP 301.
    pub working_variant: Option<&'static str>,
    /// Whether the fixed 256-byte fallback was tried.
    pub fallback_used: bool,
    /// Every attempt in order.
    pub attempts: Vec<AttemptDump>,
}

/// One hop of the user-confirm exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuationHopDump {
    /// Requested URL, with session query values redacted.
    pub url: String,
    /// Response status.
    pub status_code: u16,
    /// Response reason.
    pub reason: String,
    /// Response headers, redacted.
    pub headers: Vec<HeaderDump>,
}

/// The user-confirm HTML, marked as actually captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuationPageDump {
    /// Always `captured`: these are real served bytes.
    pub state: &'static str,
    /// Whether the page was capped at 8192 bytes.
    pub truncated: bool,
    /// Redacted HTML.
    pub html: String,
}

/// The user-confirm step, present even when it was not needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuationDump {
    /// Whether the gateway required the confirmation form.
    pub needed: bool,
    /// Every hop: the GET chain and the continuation POST.
    pub hops: Vec<ContinuationHopDump>,
    /// The served page, when one was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<ContinuationPageDump>,
}

/// The best-effort logout performed after `config --live`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogoutDump {
    /// `attempted` or `skipped`.
    pub state: &'static str,
    /// HTTP status, when a response arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Response reason, when a response arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Response headers, redacted.
    pub headers: Vec<HeaderDump>,
    /// Transport error, when the request did not complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl LogoutDump {
    /// A logout skipped by `--keep-session`.
    pub fn skipped() -> Self {
        Self {
            state: "skipped",
            status_code: None,
            reason: None,
            headers: Vec::new(),
            error: None,
        }
    }

    /// A logout response, whether or not the gateway accepted it.
    pub fn from_response(response: &HttpResponse) -> Self {
        Self {
            state: "attempted",
            status_code: Some(response.status_code),
            reason: Some(response.reason.clone()),
            headers: redact_headers(&response.headers),
            error: None,
        }
    }

    /// A logout that failed before a response was received.
    pub fn from_error(error: &str) -> Self {
        Self {
            state: "attempted",
            status_code: None,
            reason: None,
            headers: Vec::new(),
            error: Some(error.to_owned()),
        }
    }
}

/// The complete `handshake.json` document.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Dump {
    /// Schema version of every `--json` document in this binary.
    pub schema_version: u32,
    /// Redirect chain observed before the credential POST.
    pub redirect_chain: Vec<HopDump>,
    /// Final login response.
    pub login: LoginDump,
    /// The user-confirm step, including whether it was needed.
    pub continuation: ContinuationDump,
    /// The single-session endpoint probe list.
    pub probes: Vec<ProbeDump>,
    /// Whether a config-looking response stopped the probe list early.
    pub probes_stopped_early: bool,
    /// The best-effort logout.
    pub logout: LogoutDump,
    /// Handshake attempts, absent when the connection failed before framing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake: Option<HandshakeDump>,
    /// Decoded configuration, or absent when none was obtained.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    /// Failure summary, if the command did not obtain a configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Inputs for [`render`].
pub struct DumpInput<'a> {
    /// Redirect chain from the credential-free probe.
    pub redirects: &'a [RedirectHop],
    /// Status of the final login response.
    pub login_status: u16,
    /// Reason of the final login response.
    pub login_reason: &'a str,
    /// Headers of the final login response.
    pub login_headers: &'a [(String, String)],
    /// Whether the secondary token was submitted.
    pub token_submitted: bool,
    /// Credential POST field names in wire order, never their values.
    pub login_fields: &'a [String],
    /// The user-confirm exchange, when the gateway required one.
    pub continuation: Option<&'a ContinuationObservation>,
    /// The single-session endpoint probe list.
    pub probes: &'a [ProbeObservation],
    /// Whether a config-looking response stopped the probe list early.
    pub probes_stopped_early: bool,
    /// Cookie values removed from captured HTML and probe bodies.
    pub cookie_values: &'a [String],
    /// The best-effort logout.
    pub logout: LogoutDump,
    /// Handshake observations, when the handshake was attempted.
    pub handshake: Option<&'a HandshakeOutcome>,
    /// Decoded configuration, when one was obtained.
    pub config: Option<&'a NcpConfig>,
    /// Failure summary, when the command did not succeed.
    pub error: Option<&'a str>,
}

/// Render a redacted dump document.
pub fn render(input: &DumpInput<'_>) -> Dump {
    let handshake = input.handshake.map(|outcome| HandshakeDump {
        working_variant: outcome.working_variant.map(|variant| variant.as_str()),
        fallback_used: outcome.fallback_used(),
        attempts: outcome
            .attempts
            .iter()
            .map(|attempt| AttemptDump {
                content_length_variant: attempt.variant.as_str(),
                http_status: attempt.http_status,
                http_headers: redact_headers(&attempt.http_headers),
                status_byte: attempt.status,
                frames: attempt
                    .frames
                    .iter()
                    .map(|frame| FrameDump {
                        message_number: frame.message_number,
                        declared_length: frame.declared_length,
                        body_length: frame.body.len(),
                    })
                    .collect(),
                request_hex: redact_request_hex(&attempt.request_bytes),
                response_hex: redact_response_hex(attempt),
                bytes_received: attempt.response_bytes.len(),
                read_offset_hex: attempt.read_offset.map(|offset| format!("{offset:x}")),
                transport_error: attempt.transport_error,
                error: attempt.failure.clone(),
            })
            .collect(),
    });

    Dump {
        schema_version: crate::common::DUMP_SCHEMA_VERSION,
        redirect_chain: input
            .redirects
            .iter()
            .map(|hop| HopDump {
                url: redact_url(&hop.url),
                status_code: hop.status_code,
                reason: hop.reason.clone(),
                location: hop.location.as_deref().map(redact_url),
            })
            .collect(),
        login: LoginDump {
            status_code: input.login_status,
            reason: input.login_reason.to_owned(),
            headers: redact_headers(input.login_headers),
            token_submitted: input.token_submitted,
            body_fields: input.login_fields.to_vec(),
        },
        continuation: render_continuation(input.continuation, input.cookie_values),
        probes: input
            .probes
            .iter()
            .map(|probe| render_probe(probe, input.cookie_values))
            .collect(),
        probes_stopped_early: input.probes_stopped_early,
        logout: input.logout.clone(),
        handshake,
        config: input
            .config
            .and_then(|config| serde_json::to_value(config).ok()),
        error: input.error.map(str::to_owned),
    }
}

fn render_continuation(
    observation: Option<&ContinuationObservation>,
    cookie_values: &[String],
) -> ContinuationDump {
    let Some(observation) = observation else {
        return ContinuationDump {
            needed: false,
            hops: Vec::new(),
            page: None,
        };
    };

    ContinuationDump {
        needed: true,
        hops: observation
            .hops
            .iter()
            .map(|hop| ContinuationHopDump {
                url: redact_url(&hop.url),
                status_code: hop.status_code,
                reason: hop.reason.clone(),
                headers: redact_headers(&hop.headers),
            })
            .collect(),
        page: observation.page_html.as_ref().map(|html| {
            let (slice, truncated) = truncate_utf8(html, 8192);
            ContinuationPageDump {
                state: "captured",
                truncated,
                html: redact_html_cookies(slice, cookie_values),
            }
        }),
    }
}

fn render_probe(probe: &ProbeObservation, cookie_values: &[String]) -> ProbeDump {
    ProbeDump {
        id: probe.id.to_owned(),
        method: probe.method.to_owned(),
        url: redact_url(&probe.url),
        cookies: probe.cookies.clone(),
        response: probe
            .response
            .as_ref()
            .map(|response| render_probe_response(response, cookie_values)),
        redirect: probe
            .redirect
            .as_ref()
            .map(|response| render_probe_response(response, cookie_values)),
        error: probe.error.clone(),
        config_keys: probe.config_keys,
    }
}

fn render_probe_response(
    response: &ProbeResponseObservation,
    cookie_values: &[String],
) -> ProbeResponseDump {
    ProbeResponseDump {
        status_code: response.status_code,
        reason: response.reason.clone(),
        content_type: response.content_type.clone(),
        content_length: response.content_length,
        location: response.location.as_deref().map(redact_url),
        body_hex_prefix: redacted_hex_prefix(
            &response.body,
            &response.body_ranges,
            PROBE_BODY_PREFIX,
            cookie_values,
        ),
        body_text_prefix: printable_prefix(&response.body, PROBE_BODY_PREFIX)
            .map(|text| redact_probe_text(&text, cookie_values)),
        cookies: response.cookies.clone(),
        error: response.error.clone(),
    }
}

fn redacted_hex_prefix(
    bytes: &[u8],
    ranges: &[(usize, usize)],
    limit: usize,
    cookie_values: &[String],
) -> String {
    let end = bytes.len().min(limit);
    let mut out = String::new();
    let mut cursor = 0;
    for &(start, stop) in ranges {
        if start >= end {
            break;
        }
        let stop = stop.min(end);
        if start > cursor {
            out.push_str(&hex(&bytes[cursor..start]));
        }
        if stop > start {
            out.push_str(&format!("[redacted {} bytes]", stop - start));
        }
        cursor = stop.max(cursor);
        if cursor >= end {
            break;
        }
    }
    if cursor < end {
        out.push_str(&hex(&bytes[cursor..end]));
    }

    for value in cookie_values {
        if value.is_empty() {
            continue;
        }
        let needle = hex(value.as_bytes());
        if !needle.is_empty() {
            out = out.replace(&needle, REDACTED);
        }
    }
    out
}

fn printable_prefix(bytes: &[u8], limit: usize) -> Option<String> {
    let slice = &bytes[..bytes.len().min(limit)];
    if slice.is_empty() {
        return None;
    }
    let printable = slice
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || matches!(byte, b'\r' | b'\n' | b'\t' | b' '))
        .count();
    if printable * 10 < slice.len() * 9 {
        return None;
    }
    Some(String::from_utf8_lossy(slice).into_owned())
}

fn redact_probe_text(text: &str, cookie_values: &[String]) -> String {
    let redacted = Redactor::with_secrets(cookie_values.to_vec()).redact(text);
    redact_assignments(&redacted)
}

fn truncate_utf8(text: &str, max: usize) -> (&str, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

fn redact_html_cookies(html: &str, cookie_values: &[String]) -> String {
    let mut secrets: Vec<String> = cookie_values.to_vec();
    for form in parse_forms(html) {
        for input in &form.inputs {
            if !input.is_hidden() {
                continue;
            }
            if let (Some(name), Some(value)) = (input.name.as_deref(), input.value.as_deref()) {
                if is_cookie_like_key(name) && !value.is_empty() {
                    secrets.push(value.to_owned());
                }
            }
        }
    }

    let text = Redactor::with_secrets(secrets).redact(html);
    redact_assignments(&text)
}

fn is_cookie_like_key(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    is_sensitive_key(&name)
        || ["cookie", "dsid", "session", "sid", "sso", "csrf"]
            .iter()
            .any(|fragment| name.contains(fragment))
}

fn redact_assignments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut index = 0;

    while index < bytes.len() {
        let separator = bytes[index];
        if separator != b'=' && separator != b':' {
            index += 1;
            continue;
        }
        if separator == b':' && bytes.get(index + 1) == Some(&b'/') {
            index += 1;
            continue;
        }

        let mut key_start = index;
        while key_start > cursor
            && (bytes[key_start - 1].is_ascii_alphanumeric()
                || matches!(bytes[key_start - 1], b'_' | b'-' | b'#' | b'.'))
        {
            key_start -= 1;
        }
        let key = &text[key_start..index];
        if key.is_empty() || !is_cookie_like_key(key) {
            index += 1;
            continue;
        }

        let mut value_start = index + 1;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        let (value_start, value_end) = match bytes.get(value_start) {
            Some(&quote) if quote == b'"' || quote == b'\'' => {
                let start = value_start + 1;
                match bytes[start..].iter().position(|byte| *byte == quote) {
                    Some(length) => (start, start + length),
                    None => {
                        index += 1;
                        continue;
                    }
                }
            }
            _ => {
                let mut end = value_start;
                while end < bytes.len()
                    && bytes[end].is_ascii()
                    && !bytes[end].is_ascii_whitespace()
                    && !matches!(bytes[end], b'<' | b'>' | b'"' | b'\'' | b';' | b'&' | b',')
                {
                    end += 1;
                }
                (value_start, end)
            }
        };

        out.push_str(&text[cursor..value_start]);
        out.push_str(REDACTED);
        cursor = value_end;
        index = value_end;
    }

    out.push_str(&text[cursor..]);
    out
}

/// Write `handshake.json` into `directory`, creating it if needed.
///
/// On Unix the file is created with mode 0600. On Windows the per-user profile
/// ACL is the operative control.
pub fn write_dump(directory: &Path, dump: &Dump) -> AevanResult<PathBuf> {
    std::fs::create_dir_all(directory)?;
    let path = directory.join("handshake.json");
    let text = serde_json::to_string_pretty(dump)
        .map_err(|error| AevanError::Config(format!("cannot serialise dump: {error}")))?;

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(text.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(path)
}

fn redact_headers(headers: &[(String, String)]) -> Vec<HeaderDump> {
    headers
        .iter()
        .map(|(name, value)| HeaderDump {
            name: name.clone(),
            value: if is_sensitive_key(name) {
                REDACTED.to_owned()
            } else {
                value.clone()
            },
        })
        .collect()
}

fn redact_request_hex(request: &[u8]) -> String {
    let Some(header_end) = find_subslice(request, b"\r\n\r\n") else {
        return hex(request);
    };
    let header = &request[..header_end];
    let body = &request[header_end..];

    let mut redacted_header = Vec::with_capacity(header.len());
    for (index, line) in header.split(|byte| *byte == b'\n').enumerate() {
        if index != 0 {
            redacted_header.push(b'\n');
        }
        let had_cr = line.ends_with(b"\r");
        let line = if had_cr {
            &line[..line.len() - 1]
        } else {
            line
        };
        if let Some(colon) = line.iter().position(|byte| *byte == b':') {
            let name = String::from_utf8_lossy(&line[..colon]);
            if is_sensitive_key(name.trim()) {
                redacted_header.extend_from_slice(name.trim().as_bytes());
                redacted_header.extend_from_slice(b": ");
                redacted_header.extend_from_slice(REDACTED.as_bytes());
                if had_cr {
                    redacted_header.push(b'\r');
                }
                continue;
            }
        }
        redacted_header.extend_from_slice(line);
        if had_cr {
            redacted_header.push(b'\r');
        }
    }

    let mut combined = redacted_header;
    combined.extend_from_slice(body);
    hex(&combined)
}

fn redact_response_hex(attempt: &aevan_nc::HandshakeAttempt) -> String {
    let response = &attempt.response_bytes;
    let mut ranges = key_block_ranges(response);
    ranges.extend(structured_key_block_ranges(attempt));
    let ranges = merge_ranges(ranges);
    if ranges.is_empty() {
        return hex(response);
    }

    let mut out = String::new();
    let mut cursor = 0;
    for (start, end) in ranges {
        if start > cursor {
            out.push_str(&hex(&response[cursor..start]));
        }
        out.push_str(&format!("[redacted {} bytes]", end - start));
        cursor = end.max(cursor);
    }
    out.push_str(&hex(&response[cursor..]));
    out
}

pub(crate) fn key_block_ranges(response: &[u8]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut index = 0;
    while index + KEY_BLOCK_SIGNATURE.len() + KEY_BLOCK_LEN <= response.len() {
        if response[index..index + KEY_BLOCK_SIGNATURE.len()] == KEY_BLOCK_SIGNATURE {
            let start = index + KEY_BLOCK_SIGNATURE.len();
            let end = start + KEY_BLOCK_LEN;
            ranges.push((start, end));
            index = end;
        } else {
            index += 1;
        }
    }
    ranges
}

/// Locate key blocks in the assembled KMP body so a block split across records
/// is still redacted as one range.
pub(crate) fn structured_key_block_ranges(
    attempt: &aevan_nc::HandshakeAttempt,
) -> Vec<(usize, usize)> {
    let mut body = Vec::new();
    let mut frame_map = Vec::new();
    for frame in &attempt.frames {
        if frame.message_number == Some(300) {
            continue;
        }
        let start = body.len();
        body.extend_from_slice(&frame.body);
        frame_map.push((start, body.len(), frame.body_offset));
    }

    let mut raw_ranges = Vec::new();
    for (range_start, range_end) in key_block_ranges_in_body(&body) {
        for (frame_start, frame_end, raw_offset) in &frame_map {
            let start = range_start.max(*frame_start);
            let end = range_end.min(*frame_end);
            if start < end {
                let raw_start = raw_offset + (start - frame_start);
                raw_ranges.push((raw_start, raw_start + (end - start)));
            }
        }
    }
    raw_ranges
}

fn key_block_ranges_in_body(body: &[u8]) -> Vec<(usize, usize)> {
    const KMP_HEADER_LEN: usize = 20;
    if body.len() < KMP_HEADER_LEN || body[0..6] != [0u8; 6] {
        return Vec::new();
    }
    let payload_len = usize::from(u16::from_be_bytes([body[18], body[19]]));
    let payload_end = (KMP_HEADER_LEN + payload_len).min(body.len());

    let mut ranges = Vec::new();
    let mut offset = KMP_HEADER_LEN;
    while offset + 6 <= payload_end {
        let group = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let group_len = usize::try_from(u32::from_be_bytes([
            body[offset + 2],
            body[offset + 3],
            body[offset + 4],
            body[offset + 5],
        ]))
        .unwrap_or(usize::MAX);
        let group_end = offset.saturating_add(6).saturating_add(group_len);
        if group_end > payload_end {
            break;
        }

        let mut inner = offset + 6;
        while inner + 6 <= group_end {
            let attr = u16::from_be_bytes([body[inner], body[inner + 1]]);
            let attr_len = usize::try_from(u32::from_be_bytes([
                body[inner + 2],
                body[inner + 3],
                body[inner + 4],
                body[inner + 5],
            ]))
            .unwrap_or(usize::MAX);
            let value_start = inner + 6;
            let value_end = value_start.saturating_add(attr_len);
            if value_end > group_end {
                break;
            }
            if group == 7 && attr == 2 {
                ranges.push((value_start, value_end));
            }
            inner = value_end;
        }
        offset = group_end;
    }
    ranges
}

pub(crate) fn merge_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

pub(crate) fn redact_url(raw: &str) -> String {
    let Some((path, query)) = raw.split_once('?') else {
        return raw.to_owned();
    };
    let redacted = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) => format!("{name}={REDACTED}"),
            None => pair.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{redacted}")
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevan_nc::oncp::{ContentLengthVariant, HandshakeAttempt, HandshakeFrame, KmpMessageOwned};
    use aevan_nc::{ContinuationHop, ContinuationObservation, KMP_CONFIG};
    use aevan_proto::{HttpClient, RedirectHop, ScriptedTransport, Url};

    const SECRET_COOKIE: &str = "SUPER-SECRET-COOKIE-VALUE";
    const SECRET_KEY: &str = "AEVAN-SYNTHETIC-ESP-KEY-DO-NOT-LEAK";

    fn build_kmp_301() -> (Vec<u8>, Vec<u8>) {
        let mut key_block = [0u8; 0x40];
        key_block[..SECRET_KEY.len()].copy_from_slice(SECRET_KEY.as_bytes());
        key_block[SECRET_KEY.len()..].copy_from_slice(&[0x5a; 0x40 - SECRET_KEY.len()]);

        let mut payload = Vec::new();
        // Group 6 (MTU).
        payload.extend_from_slice(&6u16.to_be_bytes());
        payload.extend_from_slice(&10u32.to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(&4u32.to_be_bytes());
        payload.extend_from_slice(&1396u32.to_be_bytes());
        // Group 7 (SPI and ESP key block).
        payload.extend_from_slice(&7u16.to_be_bytes());
        payload.extend_from_slice(&0x50u32.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&4u32.to_be_bytes());
        payload.extend_from_slice(&0x1a2b_3c4du32.to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(&0x40u32.to_be_bytes());
        payload.extend_from_slice(&key_block);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x00; 6]);
        body.extend_from_slice(&KMP_CONFIG.to_be_bytes());
        body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        body.extend_from_slice(&payload);
        (body, payload)
    }

    fn outcome() -> HandshakeOutcome {
        let (body, payload) = build_kmp_301();
        let mut response_bytes = Vec::new();
        response_bytes.extend_from_slice(&((body.len() + 1) as u16).to_le_bytes());
        response_bytes.push(0);
        response_bytes.extend_from_slice(&body);
        let frame = HandshakeFrame {
            declared_length: body.len(),
            body,
            body_offset: 3,
            message_number: Some(KMP_CONFIG),
        };
        let message = KmpMessageOwned {
            number: KMP_CONFIG,
            record_length: 2 + frame.body.len(),
            payload,
        };
        let attempt = HandshakeAttempt {
            variant: ContentLengthVariant::Actual,
            http_status: Some(200),
            http_reason: Some("OK".into()),
            http_headers: vec![("Content-Type".into(), "text/html".into())],
            status: Some(0),
            frames: vec![frame],
            message: Some(message),
            request_bytes: format!(
                "POST /dana/js?prot=1&svc=4 HTTP/1.1\r\nCookie: DSID={SECRET_COOKIE}\r\nContent-Length: 24\r\n\r\n"
            )
            .into_bytes(),
            response_bytes,
            read_offset: None,
            transport_error: false,
            failure: None,
        };
        HandshakeOutcome {
            attempts: vec![attempt],
            working_variant: Some(ContentLengthVariant::Actual),
            message: None,
        }
    }

    fn input<'a>(
        outcome: &'a HandshakeOutcome,
        redirects: &'a [RedirectHop],
        headers: &'a [(String, String)],
    ) -> DumpInput<'a> {
        DumpInput {
            redirects,
            login_status: 302,
            login_reason: "Found",
            login_headers: headers,
            token_submitted: true,
            login_fields: &[],
            continuation: None,
            probes: &[],
            probes_stopped_early: false,
            cookie_values: &[],
            logout: LogoutDump::skipped(),
            handshake: Some(outcome),
            config: None,
            error: None,
        }
    }

    #[test]
    fn dump_redacts_set_cookie_cookie_header_and_esp_key_block() {
        let outcome = outcome();
        let redirects = vec![RedirectHop {
            url: format!("https://example.net/welcome?DSID={SECRET_COOKIE}"),
            status_code: 302,
            reason: "Found".into(),
            location: Some(format!("/next?session={SECRET_COOKIE}")),
        }];
        let headers = vec![(
            "Set-Cookie".to_owned(),
            format!("DSID={SECRET_COOKIE}; Path=/; Secure"),
        )];
        let dump = render(&input(&outcome, &redirects, &headers));
        let json = serde_json::to_string_pretty(&dump).expect("json");

        assert!(
            !json.contains(SECRET_COOKIE),
            "cookie must never appear: {json}"
        );
        assert!(
            !json.contains(SECRET_KEY),
            "ESP key must never appear: {json}"
        );
        assert!(json.contains("[REDACTED]"));
        assert!(json.contains("[redacted 64 bytes]"));
        assert!(json.contains("\"frames\""));
        assert!(json.contains("\"message_number\": 301"));

        let key_hex = SECRET_KEY
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!json.contains(&key_hex));
    }

    fn continuation_input<'a>(
        observation: &'a ContinuationObservation,
        cookie_values: &'a [String],
        logout: LogoutDump,
    ) -> DumpInput<'a> {
        DumpInput {
            redirects: &[],
            login_status: 302,
            login_reason: "Found",
            login_headers: &[],
            token_submitted: true,
            login_fields: &[],
            continuation: Some(observation),
            probes: &[],
            probes_stopped_early: false,
            cookie_values,
            logout,
            handshake: None,
            config: None,
            error: None,
        }
    }

    #[test]
    fn continuation_dump_captures_and_redacts_the_served_page() {
        let page = format!(
            "<form action=\"welcome.cgi\" method=\"post\">             <input type=\"hidden\" name=\"DSID\" value=\"{SECRET_COOKIE}\">             <input type=\"submit\" name=\"btnContinue\" value=\"Continue\">             </form><script>var session=\"{SECRET_COOKIE}\";</script>"
        );
        let observation = ContinuationObservation {
            hops: vec![ContinuationHop {
                url: format!("https://example.net/welcome?DSID={SECRET_COOKIE}"),
                status_code: 200,
                reason: "OK".into(),
                headers: vec![("Set-Cookie".into(), format!("DSID={SECRET_COOKIE}; Path=/"))],
            }],
            page_html: Some(page),
        };
        let cookies = vec![SECRET_COOKIE.to_owned()];
        let dump = render(&continuation_input(
            &observation,
            &cookies,
            LogoutDump::skipped(),
        ));
        let json = serde_json::to_string_pretty(&dump).expect("json");

        assert!(dump.continuation.needed);
        let page = dump.continuation.page.as_ref().expect("captured page");
        assert_eq!(page.state, "captured");
        assert!(!page.truncated);
        assert!(!json.contains(SECRET_COOKIE), "cookie leaked: {json}");
        assert!(json.contains("[REDACTED]"));
        assert!(json.contains("btnContinue"));
    }

    #[test]
    fn continuation_page_is_capped_at_8192_bytes() {
        let page = format!("<html>{}</html>", "a".repeat(9000));
        let observation = ContinuationObservation {
            hops: Vec::new(),
            page_html: Some(page),
        };
        let dump = render(&continuation_input(
            &observation,
            &[],
            LogoutDump::skipped(),
        ));
        let page = dump.continuation.page.as_ref().expect("captured page");
        assert!(page.truncated);
        assert!(page.html.len() <= 8192);
    }

    #[test]
    fn transport_failure_dump_keeps_partial_bytes_and_the_offset() {
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let attempt = HandshakeAttempt {
            variant: ContentLengthVariant::Actual,
            http_status: Some(200),
            http_reason: Some("OK".into()),
            http_headers: Vec::new(),
            status: None,
            frames: Vec::new(),
            message: None,
            request_bytes: b"POST /dana/js?prot=1&svc=4 HTTP/1.1\r\n\r\n".to_vec(),
            response_bytes: partial.to_vec(),
            read_offset: Some(partial.len()),
            transport_error: true,
            failure: Some("transport read: peer closed".into()),
        };
        let outcome = HandshakeOutcome {
            attempts: vec![attempt],
            working_variant: None,
            message: None,
        };
        let dump = render(&DumpInput {
            redirects: &[],
            login_status: 302,
            login_reason: "Found",
            login_headers: &[],
            token_submitted: false,
            login_fields: &[],
            continuation: None,
            probes: &[],
            probes_stopped_early: false,
            cookie_values: &[],
            logout: LogoutDump::skipped(),
            handshake: Some(&outcome),
            config: None,
            error: Some("transport"),
        });
        let json = serde_json::to_string_pretty(&dump).expect("json");
        assert!(json.contains("\"bytes_received\""));
        assert!(json.contains(&format!("\"read_offset_hex\": \"{:x}\"", partial.len())));
        assert!(json.contains("\"transport_error\": true"));
        assert!(json.contains(&hex(partial)));
    }

    fn probe_observation(
        cookies: CookieDiagnostics,
        body: &[u8],
    ) -> (ProbeObservation, ProbeResponseObservation) {
        let response = ProbeResponseObservation {
            status_code: Some(200),
            reason: Some("OK".into()),
            content_type: Some("text/plain".into()),
            content_length: Some(body.len() as u64),
            location: Some(format!("/next?token={SECRET_COOKIE}")),
            body: body.to_vec(),
            body_ranges: Vec::new(),
            cookies: cookies.clone(),
            error: None,
        };
        let probe = ProbeObservation {
            id: "ncrun",
            method: "GET",
            url: format!("https://example.net/dana/nc/ncrun.cgi?launch_nc={SECRET_COOKIE}"),
            cookies,
            response: Some(response.clone()),
            redirect: None,
            error: None,
            config_keys: false,
        };
        (probe, response)
    }

    #[test]
    fn probe_dump_records_an_empty_cookie_jar() {
        let mut client = HttpClient::new(ScriptedTransport::new([]));
        let url = Url::parse("https://example.net/dana/nc/ncrun.cgi").expect("url");
        let cookies = client.cookie_jar_mut().diagnostics(&url);
        let (probe, _) = probe_observation(cookies, b"<html>sign in</html>");

        let dump = render(&DumpInput {
            redirects: &[],
            login_status: 302,
            login_reason: "Found",
            login_headers: &[],
            token_submitted: false,
            login_fields: &[],
            continuation: None,
            probes: std::slice::from_ref(&probe),
            probes_stopped_early: false,
            cookie_values: &[],
            logout: LogoutDump::skipped(),
            handshake: None,
            config: None,
            error: None,
        });
        let json = serde_json::to_string_pretty(&dump).expect("json");

        assert!(json.contains("\"probes\""));
        assert!(json.contains("\"jar_size\": 0"));
        assert!(json.contains("\"header_empty\": true"));
        assert!(json.contains("launch_nc=[REDACTED]"));
    }

    #[test]
    fn probe_dump_never_contains_a_cookie_value() {
        let login_url = Url::parse("https://example.net/dana-na/auth/login.cgi").expect("url");
        let set_cookie = HttpResponse {
            status_code: 200,
            reason: "OK".into(),
            headers: vec![(
                "Set-Cookie".to_owned(),
                format!("DSID={SECRET_COOKIE}; Path=/"),
            )],
            body: Vec::new(),
        };
        let mut client = HttpClient::new(ScriptedTransport::new([]));
        client
            .cookie_jar_mut()
            .store_from_response(&login_url, &set_cookie);
        let secrets = client.cookie_jar().secret_values();
        let cookies = client.cookie_jar_mut().diagnostics(&login_url);
        let body = format!("welcome DSID={SECRET_COOKIE} raw {SECRET_COOKIE}");
        let (probe, _) = probe_observation(cookies, body.as_bytes());

        let dump = render(&DumpInput {
            redirects: &[],
            login_status: 302,
            login_reason: "Found",
            login_headers: &[],
            token_submitted: false,
            login_fields: &[],
            continuation: None,
            probes: std::slice::from_ref(&probe),
            probes_stopped_early: false,
            cookie_values: &secrets,
            logout: LogoutDump::skipped(),
            handshake: None,
            config: None,
            error: None,
        });
        let json = serde_json::to_string_pretty(&dump).expect("json");

        assert!(!json.contains(SECRET_COOKIE), "cookie leaked: {json}");
        assert!(json.contains("DSID"));
    }

    #[test]
    fn response_redaction_keeps_the_bytes_before_and_after_the_key_block() {
        let outcome = outcome();
        let attempt = &outcome.attempts[0];
        let key_start = attempt
            .response_bytes
            .windows(KEY_BLOCK_SIGNATURE.len())
            .position(|window| window == KEY_BLOCK_SIGNATURE)
            .expect("key block signature")
            + KEY_BLOCK_SIGNATURE.len();
        let rendered = redact_response_hex(attempt);
        assert!(rendered.starts_with(&hex(&attempt.response_bytes[..key_start])));
        assert!(rendered.contains("[redacted 64 bytes]"));
        assert!(!rendered.contains(SECRET_KEY));
    }

    #[test]
    fn login_dump_records_body_field_names_but_no_values() {
        let outcome = outcome();
        let fields: Vec<String> = [
            "username",
            "password",
            "realm",
            "xsauth",
            "tz_offset",
            "clienttime",
            "url",
            "activex_enabled",
            "java_enabled",
        ]
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
        let mut input = input(&outcome, &[], &[]);
        input.login_fields = &fields;

        let dump = render(&input);
        let json = serde_json::to_string_pretty(&dump).expect("json");

        assert_eq!(dump.login.body_fields, fields);
        assert!(json.contains("\"xsauth\""));
        assert!(!json.contains("0123456789abcdef"));
        assert!(!json.contains("hunter2"));
    }
}
