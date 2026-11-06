//! A small redirect-following HTTP client with a cookie jar.
//!
//! The transport is a trait so every redirect, cookie and form test can run
//! without opening a socket. [`TlsTransport`] is the only implementation that
//! touches the network, and only `auth-probe` and `login` construct it.

use std::collections::VecDeque;
use std::fmt;
use std::io::{Read, Write};
use std::time::Duration;

use rustls::StreamOwned;
use serde::Serialize;

use crate::cookies::CookieJar;
use crate::error::ProtoError;
use crate::http::{parse_response, HttpRequest, HttpResponse};
use crate::tls::{self, TlsObservation, MAX_RESPONSE_BYTES};
use crate::url::Url;

/// Default maximum number of redirects to follow.
pub const DEFAULT_MAX_REDIRECTS: usize = 5;

/// One response in a redirect chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedirectHop {
    /// URL that was requested.
    pub url: String,
    /// Response status.
    pub status_code: u16,
    /// Response reason phrase.
    pub reason: String,
    /// Raw `Location` header, if present.
    pub location: Option<String>,
}

/// The complete result of a redirect-following `GET`.
#[derive(Clone, PartialEq, Eq)]
pub struct FollowedResponse {
    /// Every response observed, in request order, including the final one.
    pub hops: Vec<RedirectHop>,
    /// URL of the final response.
    pub final_url: Url,
    /// Final status code.
    pub status_code: u16,
    /// Final reason phrase.
    pub reason: String,
    /// Final headers.
    pub headers: Vec<(String, String)>,
    /// Final body.
    pub body: Vec<u8>,
    /// Whether the redirect limit stopped further following.
    pub redirect_limit_reached: bool,
}

impl fmt::Debug for FollowedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FollowedResponse")
            .field("hops", &self.hops)
            .field("final_url", &self.final_url.to_string())
            .field("status_code", &self.status_code)
            .field("reason", &self.reason)
            .field("body_bytes", &self.body.len())
            .field("redirect_limit_reached", &self.redirect_limit_reached)
            .finish()
    }
}

impl FollowedResponse {
    /// Look up a final-response header case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Final body as lossy UTF-8.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// The byte-level transport used by [`HttpClient`].
///
/// Implementations must perform exactly one request per call and must not
/// follow redirects themselves.
pub trait HttpTransport {
    /// Execute one request.
    fn execute(&mut self, request: &HttpRequest) -> Result<HttpResponse, ProtoError>;

    /// TLS facts from the first connection, if the transport observed any.
    fn tls_observation(&self) -> Option<&TlsObservation> {
        None
    }
}

/// TLS transport implemented with `rustls`.
pub struct TlsTransport {
    timeout: Duration,
    observation: Option<TlsObservation>,
}

impl TlsTransport {
    /// Create a transport whose sockets have the given read/write timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            observation: None,
        }
    }
}

impl HttpTransport for TlsTransport {
    fn execute(&mut self, request: &HttpRequest) -> Result<HttpResponse, ProtoError> {
        let (connection, socket) = tls::connect(&request.url, self.timeout)?;
        if self.observation.is_none() {
            self.observation = Some(tls::observe(&connection)?);
        }

        let mut stream = StreamOwned::new(connection, socket);
        stream
            .write_all(&request.encode()?)
            .map_err(ProtoError::Io)?;
        stream.flush().map_err(ProtoError::Io)?;

        let mut raw = Vec::new();
        let mut limited = stream.take(MAX_RESPONSE_BYTES);
        let read_error = limited.read_to_end(&mut raw).err();
        if raw.len() as u64 >= MAX_RESPONSE_BYTES {
            return Err(ProtoError::Http(format!(
                "response exceeds the {MAX_RESPONSE_BYTES}-byte limit"
            )));
        }

        match parse_response(&raw) {
            Ok(response) => Ok(response),
            Err(parse_error) => match read_error {
                Some(error) => Err(ProtoError::Io(error)),
                None => Err(parse_error),
            },
        }
    }

    fn tls_observation(&self) -> Option<&TlsObservation> {
        self.observation.as_ref()
    }
}

/// A cookie-aware, redirect-following HTTP client.
pub struct HttpClient<T: HttpTransport> {
    transport: T,
    cookies: CookieJar,
    max_redirects: usize,
}

impl<T: HttpTransport> HttpClient<T> {
    /// Create a client with the default hop limit (5).
    pub fn new(transport: T) -> Self {
        Self::with_max_redirects(transport, DEFAULT_MAX_REDIRECTS)
    }

    /// Create a client with an explicit hop limit.
    pub fn with_max_redirects(transport: T, max_redirects: usize) -> Self {
        Self {
            transport,
            cookies: CookieJar::new(),
            max_redirects,
        }
    }

    /// The underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The current cookie jar.
    pub fn cookie_jar(&self) -> &CookieJar {
        &self.cookies
    }

    /// The current cookie jar, for callers that need to purge or build a header.
    pub fn cookie_jar_mut(&mut self) -> &mut CookieJar {
        &mut self.cookies
    }

    /// Perform a redirect-following `GET`.
    pub fn get(&mut self, url: &Url) -> Result<FollowedResponse, ProtoError> {
        let mut current = url.clone();
        let mut hops = Vec::new();
        let mut followed = 0;

        loop {
            let mut request = HttpRequest::get(current.clone());
            if let Some(cookie) = self.cookies.cookie_header(&current) {
                request = request.with_header("Cookie", cookie);
            }

            let response = self.transport.execute(&request)?;
            self.cookies.store_from_response(&current, &response);

            let location = response.location().map(str::to_owned);
            hops.push(RedirectHop {
                url: current.to_string(),
                status_code: response.status_code,
                reason: response.reason.clone(),
                location: location.clone(),
            });

            if response.is_redirect() {
                if followed >= self.max_redirects {
                    return Ok(FollowedResponse {
                        hops,
                        final_url: current,
                        status_code: response.status_code,
                        reason: response.reason,
                        headers: response.headers,
                        body: response.body,
                        redirect_limit_reached: true,
                    });
                }
                if let Some(location) = location {
                    current = current.join(&location)?;
                    followed += 1;
                    continue;
                }
            }

            return Ok(FollowedResponse {
                hops,
                final_url: current,
                status_code: response.status_code,
                reason: response.reason,
                headers: response.headers,
                body: response.body,
                redirect_limit_reached: false,
            });
        }
    }

    /// Perform exactly one `GET`. Redirects are not followed automatically.
    ///
    /// This is the building block for protocol steps that need each hop's
    /// status and headers, such as the login continuation exchange.
    pub fn get_once(&mut self, url: &Url) -> Result<HttpResponse, ProtoError> {
        let mut request = HttpRequest::get(url.clone());
        if let Some(cookie) = self.cookies.cookie_header(url) {
            request = request.with_header("Cookie", cookie);
        }

        let response = self.transport.execute(&request)?;
        self.cookies.store_from_response(url, &response);
        Ok(response)
    }

    /// Perform exactly one `GET` with an explicit `Cookie` header.
    ///
    /// This is for protocol steps such as the endpoint probe that must send
    /// every host-matching session cookie even when the request path is
    /// outside the cookie's path. `Set-Cookie` responses still update the jar.
    /// The header value is never logged.
    pub fn get_once_with_cookie_header(
        &mut self,
        url: &Url,
        cookie_header: Option<&str>,
    ) -> Result<HttpResponse, ProtoError> {
        let mut request = HttpRequest::get(url.clone());
        if let Some(cookie) = cookie_header {
            request = request.with_header("Cookie", cookie);
        }

        let response = self.transport.execute(&request)?;
        self.cookies.store_from_response(url, &response);
        Ok(response)
    }

    /// Perform exactly one `POST`. Redirects are not followed automatically:
    /// the caller classifies the response and decides whether it is a token
    /// challenge, a rejection or a success.
    pub fn post(
        &mut self,
        url: &Url,
        content_type: &str,
        body: &[u8],
    ) -> Result<HttpResponse, ProtoError> {
        let mut request = HttpRequest::post(url.clone(), content_type, body.to_vec());
        if let Some(cookie) = self.cookies.cookie_header(url) {
            request = request.with_header("Cookie", cookie);
        }

        let response = self.transport.execute(&request)?;
        self.cookies.store_from_response(url, &response);
        Ok(response)
    }
}

/// A transport that returns scripted responses. Tests use it; it is public so
/// callers can exercise the stages without a network.
#[derive(Default)]
pub struct ScriptedTransport {
    responses: VecDeque<HttpResponse>,
    observation: Option<TlsObservation>,
    requests: Vec<HttpRequest>,
}

impl ScriptedTransport {
    /// Build a transport from responses returned in order.
    pub fn new(responses: impl IntoIterator<Item = HttpResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            observation: None,
            requests: Vec::new(),
        }
    }

    /// Attach a TLS observation.
    pub fn with_observation(mut self, observation: TlsObservation) -> Self {
        self.observation = Some(observation);
        self
    }

    /// Requests seen so far.
    pub fn requests(&self) -> &[HttpRequest] {
        &self.requests
    }
}

impl HttpTransport for ScriptedTransport {
    fn execute(&mut self, request: &HttpRequest) -> Result<HttpResponse, ProtoError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .ok_or_else(|| ProtoError::Http("scripted transport ran out of responses".into()))
    }

    fn tls_observation(&self) -> Option<&TlsObservation> {
        self.observation.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn follows_redirects_and_carries_cookies() {
        let first = response(
            302,
            vec![
                ("Location", "/example_realm/login"),
                ("Set-Cookie", "pre=1; Path=/; Secure; HttpOnly"),
            ],
            "",
        );
        let second = response(200, vec![], "<form id=\"frmLogin\"></form>");
        let transport = ScriptedTransport::new([first, second]);
        let mut client = HttpClient::new(transport);

        let result = client
            .get(&Url::parse("https://example.net/").expect("url"))
            .expect("get");

        assert_eq!(result.hops.len(), 2);
        assert_eq!(result.hops[0].status_code, 302);
        assert_eq!(
            result.hops[0].location.as_deref(),
            Some("/example_realm/login")
        );
        assert_eq!(
            result.final_url.to_string(),
            "https://example.net/example_realm/login"
        );
        assert_eq!(result.status_code, 200);
        assert!(result.body_text().contains("frmLogin"));
        assert!(!result.redirect_limit_reached);

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1]
            .headers
            .iter()
            .any(|(name, value)| name == "Cookie" && value == "pre=1"));
    }

    #[test]
    fn stops_at_the_hop_limit_and_reports_it() {
        let redirect = || response(302, vec![("Location", "/next")], "");
        let transport = ScriptedTransport::new([redirect(), redirect(), redirect()]);
        let mut client = HttpClient::with_max_redirects(transport, 2);

        let result = client
            .get(&Url::parse("https://example.net/").expect("url"))
            .expect("get");
        assert!(result.redirect_limit_reached);
        assert_eq!(result.hops.len(), 3);
        assert_eq!(result.status_code, 302);
    }

    #[test]
    fn post_is_exactly_one_request_and_does_not_follow() {
        let transport =
            ScriptedTransport::new([response(302, vec![("Location", "/welcome.cgi")], "")]);
        let mut client = HttpClient::new(transport);
        let result = client
            .post(
                &Url::parse("https://example.net/login.cgi").expect("url"),
                "application/x-www-form-urlencoded",
                b"username=a&password=b",
            )
            .expect("post");

        assert_eq!(result.status_code, 302);
        let requests = client.transport().requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].body, b"username=a&password=b");
        assert!(requests[0]
            .headers
            .iter()
            .any(|(name, _)| name == "Content-Type"));
    }

    #[test]
    fn explicit_cookie_header_is_sent_regardless_of_path() {
        let transport = ScriptedTransport::new([response(
            200,
            vec![("Set-Cookie", "fresh=1; Path=/dana")],
            "",
        )]);
        let mut client = HttpClient::new(transport);
        let url = Url::parse("https://example.net/dana/nc/ncrun.cgi").expect("url");

        let response = client
            .get_once_with_cookie_header(&url, Some("DSID=abc"))
            .expect("get");
        assert_eq!(response.status_code, 200);

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "Cookie" && value == "DSID=abc"));
        assert_eq!(client.cookie_jar().len(), 1);
    }

    #[test]
    fn request_debug_does_not_print_the_body() {
        let request = HttpRequest::post(
            Url::parse("https://example.net/login.cgi").expect("url"),
            "application/x-www-form-urlencoded",
            b"password=super-secret".to_vec(),
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("body_bytes"));
    }
}
