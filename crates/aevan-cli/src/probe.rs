//! Single-session endpoint probe for the post-login configuration.
//!
//! `/dana/js?prot=1&svc=4` is the legacy oNCP entry. On this gateway it
//! redirects to the auth page instead of switching the TLS stream to binary
//! KMP. Network Connect is launched through
//! `/dana/nc/ncrun.cgi?launch_nc=1`, so the live command probes that launch
//! path and the other known endpoints in one authenticated session before it
//! falls back to the legacy oNCP exchange.
//!
//! Every probe records its cookie metadata (never values), HTTP facts and a
//! bounded body prefix. Probe failures are recorded and do not abort the run.

use std::time::Duration;

use aevan_nc::{
    decode_attributes, handshake_live, HandshakeAttempt, HandshakeError, HandshakeOutcome,
    KmpFrame, KmpMessageOwned, NcpConfig, HANDSHAKE_TARGET, KMP_CONFIG,
};
use aevan_proto::{CookieDiagnostics, HttpClient, HttpResponse, HttpTransport, Url};

use crate::dump;

/// Short per-request timeout used by the probe list.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Ceiling for the oNCP handshake, which opens its own TLS session.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(25);

/// How a probe reaches the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMethod {
    /// A plain HTTP `GET`.
    Get,
    /// The legacy oNCP `POST` with the hostname packet and binary switch.
    Oncp,
}

impl ProbeMethod {
    /// Stable HTTP method name for the dump.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Oncp => "POST",
        }
    }
}

/// One endpoint in the ordered probe list.
#[derive(Debug, Clone, Copy)]
pub struct ProbeSpec {
    /// Stable short name used by the dump and the failure summary.
    pub id: &'static str,
    /// Request method.
    pub method: ProbeMethod,
    /// Request target, relative to the gateway base.
    pub target: &'static str,
}

/// The ordered probe list.
///
/// The oNCP handshake runs first. It is the only probe that can produce a
/// configuration, and the gateway stops accepting fresh connections from the
/// same client after a handful in one session: when it ran fourth, its TCP
/// connect timed out (`WSAETIMEDOUT`) while the three GET probes had already
/// opened and closed connections. Diagnostics come after it, and only run when
/// it fails.
pub const PROBES: &[ProbeSpec] = &[
    ProbeSpec {
        id: "oncp",
        method: ProbeMethod::Oncp,
        target: HANDSHAKE_TARGET,
    },
    ProbeSpec {
        id: "ncrun",
        method: ProbeMethod::Get,
        target: "/dana/nc/ncrun.cgi?launch_nc=1",
    },
    ProbeSpec {
        id: "nc_gina_ver",
        method: ProbeMethod::Get,
        target: "/dana/nc/nc_gina_ver.txt",
    },
    ProbeSpec {
        id: "am_params",
        method: ProbeMethod::Get,
        target: "/dana/home/am_params.cgi?am=0",
    },
];

/// HTTP and body facts for one response, with any ESP key block located.
#[derive(Debug, Clone)]
pub struct ProbeResponseObservation {
    /// HTTP status, absent when no response arrived.
    pub status_code: Option<u16>,
    /// HTTP reason phrase, absent when no response arrived.
    pub reason: Option<String>,
    /// `Content-Type` header.
    pub content_type: Option<String>,
    /// `Content-Length` header parsed as a number.
    pub content_length: Option<u64>,
    /// `Location` header, unredacted until the dump is rendered.
    pub location: Option<String>,
    /// Body bytes, or the raw handshake response for the oNCP probe.
    pub body: Vec<u8>,
    /// Byte ranges in `body` that carry ESP key material.
    pub body_ranges: Vec<(usize, usize)>,
    /// Cookie metadata for the request that produced this response.
    pub cookies: CookieDiagnostics,
    /// Attempt-level failure, when the response was not usable.
    pub error: Option<String>,
}

/// One executed probe.
#[derive(Debug, Clone)]
pub struct ProbeObservation {
    /// Stable probe id.
    pub id: &'static str,
    /// HTTP method name.
    pub method: &'static str,
    /// Request URL, unredacted until the dump is rendered.
    pub url: String,
    /// Cookie metadata for the request.
    pub cookies: CookieDiagnostics,
    /// The first response.
    pub response: Option<ProbeResponseObservation>,
    /// The single redirect target that was followed, if any.
    pub redirect: Option<ProbeResponseObservation>,
    /// Request-level failure, for example a timeout before any response.
    pub error: Option<String>,
    /// Whether the body carries NC configuration keys without a KMP 301.
    pub config_keys: bool,
}

/// The complete probe run.
pub struct ProbeRun {
    /// Every executed probe in order. The list is shorter than [`PROBES`] when
    /// a config-looking response stopped it early.
    pub probes: Vec<ProbeObservation>,
    /// Decoded configuration, when some probe returned a KMP 301.
    pub config: Option<NcpConfig>,
    /// The legacy oNCP handshake observation, when that probe ran.
    pub handshake: Option<HandshakeOutcome>,
    /// Whether a config-looking response stopped the list early.
    pub stopped_early: bool,
}

/// The byte-stream handshake used by the oNCP probe.
pub trait OncpRunner {
    /// Execute the single oNCP handshake, including its one content-length
    /// fallback. It must not authenticate again.
    fn run(
        &mut self,
        url: &Url,
        hostname: &str,
        cookie_header: Option<&str>,
        timeout: Duration,
    ) -> Result<HandshakeOutcome, HandshakeError>;
}

/// The real runner: a fresh TLS connection with the existing session cookies.
pub struct LiveOncpRunner;

impl OncpRunner for LiveOncpRunner {
    fn run(
        &mut self,
        url: &Url,
        hostname: &str,
        cookie_header: Option<&str>,
        timeout: Duration,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        handshake_live(url, timeout, hostname, cookie_header)
    }
}

/// Execute the probe list in order against one authenticated session.
///
/// GET probes may follow at most one redirect. The oNCP probe records its
/// redirect but does not follow it: the request exists to switch the stream to
/// binary KMP, not to browse the auth page. A probe failure is recorded and the
/// list continues. The list stops early only when a response looks like a
/// configuration.
pub fn run_probes<T: HttpTransport, H: OncpRunner>(
    client: &mut HttpClient<T>,
    gateway: &Url,
    hostname: &str,
    oncp: &mut H,
    timeout: Duration,
) -> ProbeRun {
    let mut probes = Vec::new();
    let mut config = None;
    let mut handshake = None;
    let mut stopped_early = false;

    for spec in PROBES {
        let url = match gateway.join(spec.target) {
            Ok(url) => url,
            Err(error) => {
                let cookies = client.cookie_jar_mut().diagnostics(gateway);
                probes.push(ProbeObservation {
                    id: spec.id,
                    method: spec.method.as_str(),
                    url: gateway.to_string(),
                    cookies,
                    response: None,
                    redirect: None,
                    error: Some(error.to_string()),
                    config_keys: false,
                });
                continue;
            }
        };

        let cookies = client.cookie_jar_mut().diagnostics(&url);
        let cookie_header = client.cookie_jar_mut().cookie_header_for_host(&url);
        let mut observation = ProbeObservation {
            id: spec.id,
            method: spec.method.as_str(),
            url: url.to_string(),
            cookies,
            response: None,
            redirect: None,
            error: None,
            config_keys: false,
        };

        match spec.method {
            ProbeMethod::Get => {
                run_get_probe(
                    client,
                    &url,
                    cookie_header.as_deref(),
                    &mut observation,
                    &mut config,
                );
            }
            ProbeMethod::Oncp => {
                // The handshake opens its own TLS session after the login has
                // already opened several, and a fresh connect to this gateway
                // occasionally stalls. It gets a longer ceiling than the GET
                // probes; the handshake itself still runs exactly once.
                let oncp_timeout = timeout.max(HANDSHAKE_TIMEOUT);
                match oncp.run(&url, hostname, cookie_header.as_deref(), oncp_timeout) {
                    Ok(outcome) => {
                        if config.is_none() {
                            config = outcome.message.as_ref().and_then(decode_config);
                        }
                        if let Some(attempt) = outcome.last_attempt() {
                            observation.config_keys =
                                body_looks_like_config_keys(&attempt.response_bytes);
                            observation.response =
                                Some(response_from_attempt(attempt, observation.cookies.clone()));
                        }
                        handshake = Some(outcome);
                    }
                    Err(error) => observation.error = Some(error.to_string()),
                }
            }
        }

        let config_keys = observation.config_keys
            || observation
                .response
                .as_ref()
                .is_some_and(|response| body_looks_like_config_keys(&response.body))
            || observation
                .redirect
                .as_ref()
                .is_some_and(|response| body_looks_like_config_keys(&response.body));
        observation.config_keys = config_keys;

        if config.is_some() || config_keys {
            stopped_early = true;
        }
        probes.push(observation);
        if stopped_early {
            break;
        }
    }

    ProbeRun {
        probes,
        config,
        handshake,
        stopped_early,
    }
}

fn run_get_probe<T: HttpTransport>(
    client: &mut HttpClient<T>,
    url: &Url,
    cookie_header: Option<&str>,
    observation: &mut ProbeObservation,
    config: &mut Option<NcpConfig>,
) {
    let response = match client.get_once_with_cookie_header(url, cookie_header) {
        Ok(response) => response,
        Err(error) => {
            observation.error = Some(error.to_string());
            return;
        }
    };

    if config.is_none() {
        *config = config_from_response(&response);
    }
    observation.config_keys = body_looks_like_config_keys(&response.body);
    let location = response.location().map(str::to_owned);
    observation.response = Some(response_from_http(&response, observation.cookies.clone()));

    // Follow at most one redirect per probe.
    let Some(location) = location else {
        return;
    };
    let Ok(next) = url.join(&location) else {
        return;
    };
    let next_cookies = client.cookie_jar_mut().diagnostics(&next);
    let next_header = client.cookie_jar_mut().cookie_header_for_host(&next);

    match client.get_once_with_cookie_header(&next, next_header.as_deref()) {
        Ok(next_response) => {
            if config.is_none() {
                *config = config_from_response(&next_response);
            }
            observation.config_keys |= body_looks_like_config_keys(&next_response.body);
            observation.redirect = Some(response_from_http(&next_response, next_cookies));
        }
        Err(error) => {
            observation.redirect = Some(ProbeResponseObservation {
                status_code: None,
                reason: None,
                content_type: None,
                content_length: None,
                location: None,
                body: Vec::new(),
                body_ranges: Vec::new(),
                cookies: next_cookies,
                error: Some(error.to_string()),
            });
        }
    }
}

fn response_from_http(
    response: &HttpResponse,
    cookies: CookieDiagnostics,
) -> ProbeResponseObservation {
    ProbeResponseObservation {
        status_code: Some(response.status_code),
        reason: Some(response.reason.clone()),
        content_type: header(&response.headers, "content-type").map(str::to_owned),
        content_length: header(&response.headers, "content-length")
            .and_then(|value| value.parse::<u64>().ok()),
        location: header(&response.headers, "location").map(str::to_owned),
        body: response.body.clone(),
        body_ranges: dump::merge_ranges(dump::key_block_ranges(&response.body)),
        cookies,
        error: None,
    }
}

fn response_from_attempt(
    attempt: &HandshakeAttempt,
    cookies: CookieDiagnostics,
) -> ProbeResponseObservation {
    let mut ranges = dump::key_block_ranges(&attempt.response_bytes);
    ranges.extend(dump::structured_key_block_ranges(attempt));
    ProbeResponseObservation {
        status_code: attempt.http_status,
        reason: attempt.http_reason.clone(),
        content_type: header(&attempt.http_headers, "content-type").map(str::to_owned),
        content_length: header(&attempt.http_headers, "content-length")
            .and_then(|value| value.parse::<u64>().ok()),
        location: header(&attempt.http_headers, "location").map(str::to_owned),
        body: attempt.response_bytes.clone(),
        body_ranges: dump::merge_ranges(ranges),
        cookies,
        error: attempt.failure.clone(),
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn config_from_response(response: &HttpResponse) -> Option<NcpConfig> {
    if response.status_code != 200 {
        return None;
    }
    config_from_body(&response.body)
}

/// Decode a KMP 301 body, accepting only the exact framing.
pub(crate) fn config_from_body(body: &[u8]) -> Option<NcpConfig> {
    if !aevan_nc::looks_like_kmp(body) {
        return None;
    }
    let frame = KmpFrame::parse(body).ok()?;
    if frame.number != KMP_CONFIG {
        return None;
    }
    let attributes = decode_attributes(frame.payload).ok()?;
    NcpConfig::from_attributes(attributes).ok()
}

/// Decode an already parsed KMP 301 message.
pub(crate) fn decode_config(message: &KmpMessageOwned) -> Option<NcpConfig> {
    let attributes = decode_attributes(&message.payload).ok()?;
    NcpConfig::from_attributes(attributes).ok()
}

const CONFIG_KEY_HINTS: &[&str] = &[
    "ncp",
    "nc_config",
    "esp=",
    "esp_",
    "mtu=",
    "dns=",
    "wins=",
    "netmask=",
    "split_include",
    "split_exclude",
    "spi=",
];

/// Whether a body contains several NC configuration keys.
///
/// This is only an early-stop hint; a KMP 301 is still the only success.
fn body_looks_like_config_keys(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    let mut hits = 0;
    for hint in CONFIG_KEY_HINTS {
        if text.contains(hint) {
            hits += 1;
            if hits >= 2 {
                return true;
            }
        }
    }
    false
}

/// Build the exit-7 message naming every probe that ran and what it returned.
///
/// URLs have their query values redacted before they reach the message.
pub fn failure_summary(run: &ProbeRun) -> String {
    let mut parts = Vec::new();
    for probe in &run.probes {
        parts.push(format!("{}: {}", probe.id, describe_probe(probe)));
    }
    let suffix = if run.stopped_early {
        " (stopped early after a config-looking body)"
    } else {
        ""
    };
    format!(
        "no probe returned a KMP 301{suffix}; ran [{}]",
        parts.join("; ")
    )
}

fn describe_probe(probe: &ProbeObservation) -> String {
    if let Some(response) = &probe.response {
        let status = match response.status_code {
            Some(code) => format!("HTTP {code} {}", response.reason.as_deref().unwrap_or(""))
                .trim()
                .to_owned(),
            None => "no HTTP response".to_owned(),
        };
        let mut bits = vec![status];
        if let Some(content_type) = &response.content_type {
            bits.push(format!("content-type {content_type}"));
        }
        if let Some(length) = response.content_length {
            bits.push(format!("content-length {length}"));
        }
        if let Some(location) = &response.location {
            bits.push(format!("location {}", dump::redact_url(location)));
        }
        if let Some(error) = &response.error {
            bits.push(error.clone());
        }
        return bits.join(", ");
    }
    probe
        .error
        .clone()
        .unwrap_or_else(|| "no response".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevan_nc::{ContentLengthVariant, HandshakeFrame};
    use aevan_proto::{ScriptedTransport, TlsObservation};

    const KMP_301: &[u8] = include_bytes!("../../aevan-nc/tests/fixtures/ncp-config-kmp.bin");

    fn response(status: u16, headers: Vec<(&str, &str)>, body: &str) -> HttpResponse {
        HttpResponse {
            status_code: status,
            reason: String::new(),
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn binary_response(status: u16, headers: Vec<(&str, &str)>, body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status_code: status,
            reason: String::new(),
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            body,
        }
    }

    fn redirect_to_auth() -> HttpResponse {
        response(
            302,
            vec![(
                "Location",
                "https://vpn.example.net/dana-na/auth/welcome.cgi",
            )],
            "",
        )
    }

    fn observation() -> TlsObservation {
        TlsObservation {
            protocol: "TLSv1_3".into(),
            chain: Vec::new(),
        }
    }

    fn failed_handshake() -> HandshakeOutcome {
        let location = "https://vpn.example.net/dana-na/auth/welcome.cgi";
        let response_bytes = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes();
        HandshakeOutcome {
            attempts: vec![HandshakeAttempt {
                variant: ContentLengthVariant::Actual,
                http_status: Some(302),
                http_reason: Some("Found".into()),
                http_headers: vec![
                    ("Location".into(), location.to_owned()),
                    ("Content-Type".into(), "text/html".into()),
                    ("Content-Length".into(), "0".into()),
                ],
                status: None,
                frames: Vec::<HandshakeFrame>::new(),
                message: None,
                request_bytes: Vec::new(),
                response_bytes,
                read_offset: None,
                transport_error: false,
                failure: Some("unexpected HTTP status 302".into()),
            }],
            working_variant: None,
            message: None,
        }
    }

    struct ScriptedOncp {
        outcome: Option<HandshakeOutcome>,
        called: bool,
    }

    impl ScriptedOncp {
        fn returning(outcome: HandshakeOutcome) -> Self {
            Self {
                outcome: Some(outcome),
                called: false,
            }
        }
    }

    impl OncpRunner for ScriptedOncp {
        fn run(
            &mut self,
            _url: &Url,
            _hostname: &str,
            _cookie_header: Option<&str>,
            _timeout: Duration,
        ) -> Result<HandshakeOutcome, HandshakeError> {
            self.called = true;
            Ok(self.outcome.take().expect("scripted outcome"))
        }
    }

    fn gateway() -> Url {
        Url::parse("https://vpn.example.net/").expect("url")
    }

    #[test]
    fn every_endpoint_redirecting_to_the_auth_page_names_all_four() {
        // Each of the three GET probes gets a 302 and one followed 200 page.
        let auth_page = response(200, Vec::new(), "<html>sign in</html>");
        let transport = ScriptedTransport::new([
            redirect_to_auth(),
            auth_page.clone(),
            redirect_to_auth(),
            auth_page.clone(),
            redirect_to_auth(),
            auth_page,
        ])
        .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let mut oncp = ScriptedOncp::returning(failed_handshake());

        let run = run_probes(
            &mut client,
            &gateway(),
            "aevan-host",
            &mut oncp,
            Duration::from_millis(1),
        );

        assert!(run.config.is_none());
        assert!(!run.stopped_early);
        assert!(oncp.called);
        let ids: Vec<&str> = run.probes.iter().map(|probe| probe.id).collect();
        assert_eq!(ids, ["oncp", "ncrun", "nc_gina_ver", "am_params"]);
        assert_eq!(
            run.probes[1]
                .response
                .as_ref()
                .expect("response")
                .status_code,
            Some(302)
        );
        assert_eq!(
            run.probes[1]
                .redirect
                .as_ref()
                .expect("followed")
                .status_code,
            Some(200)
        );

        let summary = failure_summary(&run);
        for id in ["ncrun", "nc_gina_ver", "am_params", "oncp"] {
            assert!(summary.contains(id), "summary must name {id}: {summary}");
        }
    }

    #[test]
    fn a_kmp_301_on_the_launch_probe_decodes_and_skips_the_rest() {
        let transport = ScriptedTransport::new([binary_response(
            200,
            vec![("Content-Type", "application/octet-stream")],
            KMP_301.to_vec(),
        )])
        .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let mut oncp = ScriptedOncp::returning(failed_handshake());

        let run = run_probes(
            &mut client,
            &gateway(),
            "aevan-host",
            &mut oncp,
            Duration::from_millis(1),
        );

        assert!(run.stopped_early);
        assert_eq!(run.probes.len(), 2);
        assert_eq!(run.probes[1].id, "ncrun");
        assert!(oncp.called, "the handshake probe runs first and fails here");
        assert_eq!(
            run.config.as_ref().and_then(|config| config.mtu),
            Some(1396)
        );
        assert!(oncp.called, "the handshake probe ran first and failed");
        assert_eq!(client.transport().requests().len(), 1);
    }

    #[test]
    fn an_empty_jar_is_recorded_as_an_empty_cookie_header() {
        let auth_page = response(200, Vec::new(), "<html>sign in</html>");
        let transport = ScriptedTransport::new([
            redirect_to_auth(),
            auth_page.clone(),
            redirect_to_auth(),
            auth_page.clone(),
            redirect_to_auth(),
            auth_page,
        ])
        .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let mut oncp = ScriptedOncp::returning(failed_handshake());

        let run = run_probes(
            &mut client,
            &gateway(),
            "aevan-host",
            &mut oncp,
            Duration::from_millis(1),
        );

        for probe in &run.probes {
            assert_eq!(probe.cookies.jar_size, 0);
            assert!(probe.cookies.header_empty, "{}", probe.id);
        }
    }
}
