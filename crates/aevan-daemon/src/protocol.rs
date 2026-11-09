//! Versioned JSON-line control protocol.
//!
//! One request per line, one response per line. Every response carries
//! `schema_version`. `logs` streams one response line per record and ends a
//! non-follow stream with `done: true`.
//!
//! Credentials are accepted only as fields of a `connect` request. They are
//! held in [`SecretString`], which zeroizes on drop and redacts in `Debug`, and
//! are never part of a response or a log record.

use std::fmt;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use zeroize::Zeroizing;

use aevan_core::AevanError;

/// Version of the control protocol and of every JSON document it carries.
///
/// Version 2 lets the client resolve the profile and carry the connection
/// parameters, so a root daemon never has to read a per-user profile store.
pub const SCHEMA_VERSION: u32 = 2;

/// Oldest protocol version the daemon still accepts.
///
/// A version-1 request has no connection parameters and falls back to the
/// daemon-side profile store lookup.
pub const MIN_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted request line, including the newline.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// A credential string that zeroizes on drop and never prints itself.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The secret value.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Consume the wrapper and return the zeroizing value.
    pub fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.as_str().to_owned()))
    }
}

impl Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// One request line.
///
/// The command selects which optional fields are meaningful. Keeping the
/// envelope flat makes an old daemon reject an unknown field combination with
/// a normal typed error instead of a framing failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Protocol version.
    pub schema_version: u32,
    /// `status`, `connect`, `disconnect`, `logs` or `shutdown`.
    pub command: String,
    /// Profile name for `connect` and `disconnect`.
    ///
    /// For `connect` it is a display label in version 2; the connection
    /// parameters travel in `gateway_url` and `realm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Gateway URL for `connect` in version 2. Not secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_url: Option<String>,
    /// Authentication realm for `connect` in version 2. Not secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// Username for `connect`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password for `connect`. Never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    /// Secondary token for `connect`, when one is required. Never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<SecretString>,
    /// Follow new records for `logs`.
    #[serde(default)]
    pub follow: bool,
    /// Minimum level for `logs` (`error`, `warn`, `info`, `debug`, `trace`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Disconnect every profile for `disconnect` (one tunnel exists in M3).
    #[serde(default)]
    pub all: bool,
}

impl Request {
    /// Empty request envelope for a command.
    fn command(command: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command: command.to_owned(),
            profile: None,
            gateway_url: None,
            realm: None,
            username: None,
            password: None,
            token: None,
            follow: false,
            level: None,
            all: false,
        }
    }

    /// `status`.
    pub fn status() -> Self {
        Self::command("status")
    }

    /// `recover`: retry journal recovery and clear it when nothing remains.
    pub fn recover() -> Self {
        Self::command("recover")
    }

    /// `connect` with client-resolved connection parameters and credentials.
    pub fn connect(
        profile: Option<String>,
        gateway_url: Option<String>,
        realm: Option<String>,
        username: String,
        password: SecretString,
        token: Option<SecretString>,
    ) -> Self {
        Self {
            profile,
            gateway_url,
            realm,
            username: Some(username),
            password: Some(password),
            token,
            ..Self::command("connect")
        }
    }

    /// `disconnect`.
    pub fn disconnect(profile: Option<String>, all: bool) -> Self {
        Self {
            profile,
            all,
            ..Self::command("disconnect")
        }
    }

    /// `logs`.
    pub fn logs(follow: bool, level: Option<String>) -> Self {
        Self {
            follow,
            level,
            ..Self::command("logs")
        }
    }

    /// `shutdown`.
    pub fn shutdown() -> Self {
        Self::command("shutdown")
    }

    /// Whether this build accepts the peer's protocol version.
    ///
    /// Version 1 is still accepted so an older CLI keeps working against a new
    /// daemon; it uses the legacy store lookup.
    pub fn schema_supported(&self) -> bool {
        (MIN_SCHEMA_VERSION..=SCHEMA_VERSION).contains(&self.schema_version)
    }
}

/// One journal inverse that genuinely failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryFailure {
    /// Step name (`address`, `mtu`, `route`, `dns`, `decode`).
    pub step: String,
    /// Platform error text.
    pub reason: String,
}

/// Outcome of one crash-recovery pass.
///
/// `rolled_back` counts inverses that ran and changed something,
/// `skipped_absent` counts changes whose target was already absent, and
/// `failures` holds only genuine failures whose state may still be live.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct RecoveryReport {
    /// Inverses applied successfully.
    pub rolled_back: usize,
    /// Changes that were already undone because their target was absent.
    pub skipped_absent: usize,
    /// Genuine per-change failures. The journal is retained when non-empty.
    pub failures: Vec<RecoveryFailure>,
    /// Whether no journal file remains after this pass.
    pub removed: bool,
    /// Journal path, when the report came from a real file.
    pub journal: Option<String>,
}

impl Serialize for RecoveryReport {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // `failed` is derived so the wire document always agrees with the
        // failure list.
        let mut state = serializer.serialize_struct("RecoveryReport", 6)?;
        state.serialize_field("rolled_back", &self.rolled_back)?;
        state.serialize_field("skipped_absent", &self.skipped_absent)?;
        state.serialize_field("failed", &self.failed())?;
        state.serialize_field("failures", &self.failures)?;
        state.serialize_field("removed", &self.removed)?;
        state.serialize_field("journal", &self.journal)?;
        state.end()
    }
}

impl RecoveryReport {
    /// Number of genuine failures.
    pub fn failed(&self) -> usize {
        self.failures.len()
    }

    /// Whether nothing is left undone and the journal may be removed.
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }

    /// A report for a run with no journal present.
    pub fn clean() -> Self {
        Self {
            removed: true,
            ..Self::default()
        }
    }
}

/// One status snapshot. Contains no key material.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    /// State name.
    pub state: String,
    /// Failure reason when `state` is `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Profile name, when one has been selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Tunnel device name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Assigned address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Prefix length for `address`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
    /// Negotiated MTU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Number of applied routes.
    pub route_count: usize,
    /// Applied DNS servers.
    pub dns: Vec<String>,
    /// Bytes received from the tunnel.
    pub bytes_in: u64,
    /// Bytes sent to the tunnel.
    pub bytes_out: u64,
    /// Session uptime in seconds.
    pub uptime_secs: u64,
    /// Crash-recovery facts while an interrupted journal remains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryReport>,
}

/// One tracing record streamed by `logs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// Monotonic sequence number, used to avoid duplicates around history.
    pub seq: u64,
    /// Unix timestamp in seconds.
    pub timestamp_unix: u64,
    /// Lower-case level name.
    pub level: String,
    /// Tracing target.
    pub target: String,
    /// Rendered message and fields, already redacted.
    pub message: String,
}

/// One response line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Protocol version.
    pub schema_version: u32,
    /// Whether the request succeeded.
    pub ok: bool,
    /// Command the response belongs to.
    pub command: String,
    /// Status snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusReport>,
    /// One log record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<LogRecord>,
    /// End marker for a non-follow log stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<bool>,
    /// Error message, never containing credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Documented exit code for the error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Recovery counts, present for `recover`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryReport>,
}

impl Response {
    /// A successful response without a payload.
    pub fn ok(command: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ok: true,
            command: command.to_owned(),
            status: None,
            record: None,
            done: None,
            error: None,
            exit_code: None,
            recovery: None,
        }
    }

    /// A successful status response.
    pub fn status(command: &str, status: StatusReport) -> Self {
        Self {
            status: Some(status),
            ..Self::ok(command)
        }
    }

    /// A successful log record response.
    pub fn record(command: &str, record: LogRecord) -> Self {
        Self {
            record: Some(record),
            ..Self::ok(command)
        }
    }

    /// A non-follow log stream end marker.
    pub fn log_end(command: &str) -> Self {
        Self {
            done: Some(true),
            ..Self::ok(command)
        }
    }

    /// A successful recovery response carrying the recovery counts.
    pub fn recovered(command: &str, status: StatusReport, recovery: RecoveryReport) -> Self {
        Self {
            status: Some(status),
            recovery: Some(recovery),
            ..Self::ok(command)
        }
    }

    /// A typed failure response.
    pub fn error(command: &str, error: &AevanError) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ok: false,
            command: command.to_owned(),
            status: None,
            record: None,
            done: None,
            error: Some(error.to_string()),
            exit_code: Some(error.exit_code()),
            recovery: None,
        }
    }

    /// A failure for a request that did not parse; `command` is best effort.
    pub fn protocol_error(command: &str, message: impl Into<String>, code: i32) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ok: false,
            command: command.to_owned(),
            status: None,
            record: None,
            done: None,
            error: Some(message.into()),
            exit_code: Some(code),
            recovery: None,
        }
    }
}

impl Response {
    /// Convert a failed response back into the public error taxonomy.
    pub fn into_error(self) -> AevanError {
        if self.ok {
            return AevanError::from_exit_code(0, "the daemon reported success");
        }
        let message = self
            .error
            .unwrap_or_else(|| "the daemon reported an error".to_owned());
        AevanError::from_exit_code(self.exit_code.unwrap_or(1), message)
    }
}

/// Serialize one protocol line, including the trailing newline.
pub fn encode_line<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string(value)?;
    text.push('\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevan_core::exit_code;

    #[test]
    fn every_request_carries_the_schema_version() {
        for request in [
            Request::status(),
            Request::connect(
                Some("example".into()),
                None,
                None,
                "example_user".into(),
                SecretString::new("hunter2"),
                None,
            ),
            Request::disconnect(None, true),
            Request::recover(),
            Request::logs(true, Some("debug".into())),
            Request::shutdown(),
        ] {
            assert_eq!(request.schema_version, SCHEMA_VERSION);
            assert!(request.schema_supported());
        }
    }

    #[test]
    fn request_round_trips_and_credentials_are_redacted_in_debug() {
        let request = Request::connect(
            Some("example".into()),
            Some("https://vpn.example.net/example_realm".into()),
            Some("example_realm".into()),
            "example_user".into(),
            SecretString::new("hunter2"),
            Some(SecretString::new("123456")),
        );
        let json = serde_json::to_string(&request).expect("json");
        assert!(json.contains("hunter2"));
        let debug = format!("{request:?}");
        assert!(!debug.contains("hunter2"));
        assert!(!debug.contains("123456"));
        assert!(debug.contains("REDACTED"));

        let parsed: Request = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.command, "connect");
        assert_eq!(
            parsed.password.as_ref().map(SecretString::expose),
            Some("hunter2")
        );
        assert_eq!(
            parsed.token.as_ref().map(SecretString::expose),
            Some("123456")
        );
    }

    #[test]
    fn status_response_is_versioned_and_has_no_secret_fields() {
        let report = StatusReport {
            state: "connected".into(),
            profile: Some("example".into()),
            address: Some("10.251.98.141".into()),
            prefix_len: Some(32),
            mtu: Some(1396),
            route_count: 4,
            dns: vec!["10.251.3.18".into()],
            bytes_in: 1,
            bytes_out: 2,
            uptime_secs: 3,
            ..StatusReport::default()
        };
        let response = Response::status("status", report);
        let json = serde_json::to_string(&response).expect("json");
        assert!(json.contains("\"schema_version\":2"));
        for secret in ["password", "token", "cookie", "key", "spi"] {
            assert!(!json.contains(secret), "status leaked {secret}: {json}");
        }
    }

    #[test]
    fn recovery_reports_the_three_counts_machine_readably() {
        let report = RecoveryReport {
            rolled_back: 2,
            skipped_absent: 5,
            failures: vec![RecoveryFailure {
                step: "route".into(),
                reason: "denied".into(),
            }],
            removed: false,
            journal: Some("aevand.journal".into()),
        };
        let json = serde_json::to_string(&report).expect("json");
        assert!(json.contains("\"rolled_back\":2"), "{json}");
        assert!(json.contains("\"skipped_absent\":5"), "{json}");
        assert!(json.contains("\"failed\":1"), "{json}");
        assert!(json.contains("\"step\":\"route\""), "{json}");
        let parsed: RecoveryReport = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, report);
    }

    #[test]
    fn errors_keep_their_documented_exit_codes() {
        let response = Response::error("connect", &AevanError::AuthRejected("denied".into()));
        assert!(!response.ok);
        assert_eq!(response.exit_code, Some(exit_code::AUTH_REJECTED));
        assert_eq!(response.into_error().exit_code(), exit_code::AUTH_REJECTED);
    }

    #[test]
    fn version_one_requests_are_still_supported() {
        let mut request = Request::connect(
            Some("example".into()),
            None,
            None,
            "example_user".into(),
            SecretString::new("hunter2"),
            None,
        );
        request.schema_version = 1;
        assert!(request.schema_supported());
        assert!(json_fields_missing(&request));
    }

    fn json_fields_missing(request: &Request) -> bool {
        let json = serde_json::to_string(request).expect("json");
        !json.contains("gateway_url") && !json.contains("realm")
    }

    #[test]
    fn a_version_outside_the_supported_range_is_rejected() {
        let mut request = Request::status();
        request.schema_version = 0;
        assert!(!request.schema_supported());
        request.schema_version = SCHEMA_VERSION + 1;
        assert!(!request.schema_supported());
    }

    #[test]
    fn the_connection_parameters_round_trip() {
        let request = Request::connect(
            Some("example".into()),
            Some("https://vpn.example.net/example_realm".into()),
            Some("example_realm".into()),
            "example_user".into(),
            SecretString::new("hunter2"),
            None,
        );
        let json = serde_json::to_string(&request).expect("json");
        assert!(json.contains("\"gateway_url\":\"https://vpn.example.net/example_realm\""));
        assert!(json.contains("\"realm\":\"example_realm\""));
        let parsed: Request = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.gateway_url, request.gateway_url);
        assert_eq!(parsed.realm, request.realm);
    }

    #[test]
    fn malformed_request_fields_are_a_normal_parse_error() {
        assert!(serde_json::from_str::<Request>(r#"{"schema_version":1}"#).is_err());
    }

    #[test]
    fn encode_line_appends_one_newline() {
        let line = encode_line(&Request::status()).expect("encode");
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
    }
}
