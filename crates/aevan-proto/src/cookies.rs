//! A small RFC 6265 cookie jar.
//!
//! The NC client only talks to one gateway host, so this intentionally omits
//! the Public Suffix List and the more exotic parts of RFC 6265. It implements
//! the parts that matter for a login session: `Domain`, `Path`, `Expires`,
//! `Max-Age`, `Secure`, host-only cookies, replacement and ordered sending.
//!
//! Cookie values are secrets. [`Cookie`] and [`CookieJar`] deliberately do not
//! implement `Display`, and their `Debug` implementations print nothing that
//! came off the wire.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::http::HttpResponse;
use crate::url::Url;

/// One stored cookie.
#[derive(Clone, PartialEq, Eq)]
pub struct Cookie {
    name: String,
    value: Zeroizing<String>,
    domain: String,
    path: String,
    secure: bool,
    host_only: bool,
    expires_at: Option<SystemTime>,
    creation: u64,
}

impl Cookie {
    /// Cookie name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Cookie value. Callers must not print or log it.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Domain the cookie belongs to (lower-case).
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Path the cookie belongs to.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether the cookie may only be sent over TLS.
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Whether the cookie was set without a `Domain` attribute.
    pub fn host_only(&self) -> bool {
        self.host_only
    }

    /// Whether the cookie has expired at `now`.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.expires_at.is_some_and(|expiry| expiry <= now)
    }
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cookie(<redacted>)")
    }
}

/// Cookies collected for one browsing session.
#[derive(Clone, Default)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
    next_creation: u64,
}

impl fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieJar")
            .field("count", &self.cookies.len())
            .finish()
    }
}

/// One cookie's metadata, deliberately excluding its value.
///
/// The probe dump records what the jar would send without ever copying a
/// session secret. Values stay in [`Cookie`] and are never serialised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CookieInfo {
    /// Cookie name.
    pub name: String,
    /// Domain the cookie belongs to (lower-case).
    pub domain: String,
    /// Path the cookie belongs to.
    pub path: String,
    /// Whether the cookie requires TLS.
    pub secure: bool,
    /// Whether the cookie was set without a `Domain` attribute.
    pub host_only: bool,
    /// Whether the cookie's domain and secure flag match the request.
    pub host_applies: bool,
    /// Whether the cookie also matches the request path.
    pub path_applies: bool,
}

/// Cookie-jar facts for one request, with no cookie values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CookieDiagnostics {
    /// Total cookies stored in the jar.
    pub jar_size: usize,
    /// Cookies that match host, secure flag and request path.
    pub path_scoped_count: usize,
    /// Cookies that match host and secure flag, ignoring path.
    pub host_count: usize,
    /// Whether the `Cookie` header actually used by the probe was empty.
    ///
    /// The probe sends the host-matching header, because the oNCP endpoints
    /// are outside the login directory. A true value therefore means the jar
    /// had no applicable session cookie at all, not merely a path mismatch.
    pub header_empty: bool,
    /// Which matching rule produced the header: `host` or `path`.
    pub header_source: &'static str,
    /// Every stored cookie, metadata only.
    pub cookies: Vec<CookieInfo>,
}

impl CookieJar {
    /// An empty jar.
    pub fn new() -> Self {
        Self::default()
    }

    /// Report cookie metadata for a request without revealing any value.
    ///
    /// Both the path-scoped count and the host-only count are recorded so a
    /// dropped session cookie can be told apart from an empty jar. The probe
    /// itself uses the host-matching rule, so [`CookieDiagnostics::header_empty`]
    /// reflects that header.
    pub fn diagnostics(&mut self, url: &Url) -> CookieDiagnostics {
        self.diagnostics_at(url, SystemTime::now())
    }

    /// [`CookieJar::diagnostics`] with an explicit clock, for tests.
    pub fn diagnostics_at(&mut self, url: &Url, now: SystemTime) -> CookieDiagnostics {
        self.purge_expired(now);

        let host = url.host.to_ascii_lowercase();
        let request_path = url
            .path_and_query
            .split('?')
            .next()
            .filter(|path| !path.is_empty())
            .unwrap_or("/");

        let mut path_scoped_count = 0;
        let mut host_count = 0;
        let mut cookies = Vec::with_capacity(self.cookies.len());
        for cookie in &self.cookies {
            let domain_ok = if cookie.host_only {
                host == cookie.domain
            } else {
                domain_matches(&host, &cookie.domain)
            };
            let host_applies = domain_ok && (!cookie.secure || url.is_https());
            let path_applies = host_applies && path_matches(request_path, &cookie.path);
            if host_applies {
                host_count += 1;
            }
            if path_applies {
                path_scoped_count += 1;
            }
            cookies.push(CookieInfo {
                name: cookie.name.clone(),
                domain: cookie.domain.clone(),
                path: cookie.path.clone(),
                secure: cookie.secure,
                host_only: cookie.host_only,
                host_applies,
                path_applies,
            });
        }

        CookieDiagnostics {
            jar_size: self.cookies.len(),
            path_scoped_count,
            host_count,
            header_empty: host_count == 0,
            header_source: "host",
            cookies,
        }
    }

    /// Number of stored cookies (including ones that may have expired).
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Whether the jar is empty.
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Store every `Set-Cookie` header in `response` for `url`.
    pub fn store_from_response(&mut self, url: &Url, response: &HttpResponse) {
        self.store_from_response_at(url, response, SystemTime::now());
    }

    /// Store every `Set-Cookie` header using an explicit clock, for tests.
    pub fn store_from_response_at(&mut self, url: &Url, response: &HttpResponse, now: SystemTime) {
        for (name, value) in &response.headers {
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            if let Some(cookie) = self.parse_set_cookie(value, url, now) {
                self.insert(cookie);
            }
        }
        self.purge_expired(now);
    }

    /// Build the `Cookie` header for a request to `url`, if any cookie applies.
    ///
    /// Cookies are ordered by descending path length and then creation order,
    /// as RFC 6265 recommends. The returned string contains cookie values and
    /// must only be placed in a request, never logged.
    pub fn cookie_header(&mut self, url: &Url) -> Option<String> {
        self.cookie_header_at(url, SystemTime::now())
    }

    /// [`CookieJar::cookie_header`] with an explicit clock, for tests.
    pub fn cookie_header_at(&mut self, url: &Url, now: SystemTime) -> Option<String> {
        self.purge_expired(now);

        let mut matching: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|cookie| cookie_applies(cookie, url))
            .collect();
        matching.sort_by(|left, right| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then(left.creation.cmp(&right.creation))
        });

        if matching.is_empty() {
            return None;
        }

        let header = matching
            .iter()
            .map(|cookie| format!("{}={}", cookie.name, cookie.value.as_str()))
            .collect::<Vec<_>>()
            .join("; ");
        Some(header)
    }

    /// Build the `Cookie` header for a URL's host, ignoring path restrictions.
    ///
    /// The oNCP handshake jumps from the login path to `/dana/js` on the same
    /// origin. The gateway may scope the session cookie to the login directory,
    /// so the handshake deliberately sends every host-matching cookie.
    pub fn cookie_header_for_host(&mut self, url: &Url) -> Option<String> {
        self.cookie_header_for_host_at(url, SystemTime::now())
    }

    /// [`CookieJar::cookie_header_for_host`] with an explicit clock, for tests.
    pub fn cookie_header_for_host_at(&mut self, url: &Url, now: SystemTime) -> Option<String> {
        self.purge_expired(now);

        let host = url.host.to_ascii_lowercase();
        let mut matching: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|cookie| {
                let domain_ok = if cookie.host_only {
                    host == cookie.domain
                } else {
                    domain_matches(&host, &cookie.domain)
                };
                domain_ok && (!cookie.secure || url.is_https())
            })
            .collect();
        matching.sort_by(|left, right| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then(left.creation.cmp(&right.creation))
        });

        if matching.is_empty() {
            return None;
        }

        Some(
            matching
                .iter()
                .map(|cookie| format!("{}={}", cookie.name, cookie.value.as_str()))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Remove every cookie.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Copy every stored cookie value for a diagnostic redactor.
    ///
    /// The result contains live session secrets. It must only be used to
    /// remove those values from text, never logged, serialised or printed.
    pub fn secret_values(&self) -> Vec<String> {
        self.cookies
            .iter()
            .map(|cookie| cookie.value.to_string())
            .collect()
    }

    fn parse_set_cookie(&self, header: &str, url: &Url, now: SystemTime) -> Option<Cookie> {
        let mut parts = header.split(';');
        let pair = parts.next()?.trim();
        let (name, value) = pair.split_once('=')?;
        let name = name.trim();
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return None;
        }
        let value = value.trim().trim_matches('"');
        if value
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || byte == b';')
        {
            return None;
        }

        let request_host = url.host.to_ascii_lowercase();
        let mut domain = request_host.clone();
        let mut host_only = true;
        let mut path = default_path(&url.path_and_query);
        let mut secure = false;
        let mut expires_at = None;
        let mut max_age = None;

        for attribute in parts {
            let (key, value) = attribute
                .split_once('=')
                .map(|(key, value)| (key.trim(), value.trim()))
                .unwrap_or((attribute.trim(), ""));
            match key.to_ascii_lowercase().as_str() {
                "domain" => {
                    let candidate = value.trim_start_matches('.').to_ascii_lowercase();
                    if candidate.is_empty() || !domain_matches(&request_host, &candidate) {
                        return None;
                    }
                    domain = candidate;
                    host_only = false;
                }
                "path" => {
                    if value.starts_with('/') {
                        path = value.to_owned();
                    }
                }
                "secure" => secure = true,
                "max-age" => {
                    if let Ok(seconds) = value.parse::<i64>() {
                        max_age = Some(seconds);
                    }
                }
                "expires" => {
                    if let Some(time) = parse_http_date(value) {
                        expires_at = Some(time);
                    }
                }
                _ => {}
            }
        }

        if let Some(seconds) = max_age {
            expires_at = if seconds <= 0 {
                Some(UNIX_EPOCH)
            } else {
                now.checked_add(Duration::from_secs(seconds as u64))
            };
        }

        Some(Cookie {
            name: name.to_owned(),
            value: Zeroizing::new(value.to_owned()),
            domain,
            path,
            secure,
            host_only,
            expires_at,
            creation: 0,
        })
    }

    fn insert(&mut self, mut cookie: Cookie) {
        cookie.creation = self.next_creation;
        self.next_creation += 1;

        if let Some(existing) = self.cookies.iter_mut().find(|existing| {
            existing.name == cookie.name
                && existing.domain == cookie.domain
                && existing.path == cookie.path
        }) {
            *existing = cookie;
        } else {
            self.cookies.push(cookie);
        }
    }

    fn purge_expired(&mut self, now: SystemTime) {
        self.cookies.retain(|cookie| !cookie.is_expired(now));
    }
}

fn cookie_applies(cookie: &Cookie, url: &Url) -> bool {
    let host = url.host.to_ascii_lowercase();
    let domain_ok = if cookie.host_only {
        host == cookie.domain
    } else {
        domain_matches(&host, &cookie.domain)
    };
    if !domain_ok {
        return false;
    }
    if cookie.secure && !url.is_https() {
        return false;
    }
    let request_path = url
        .path_and_query
        .split('?')
        .next()
        .filter(|path| !path.is_empty())
        .unwrap_or("/");
    path_matches(request_path, &cookie.path)
}

fn domain_matches(host: &str, domain: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return host == domain;
    }
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    request_path == cookie_path
        || (request_path.starts_with(cookie_path)
            && (cookie_path.ends_with('/')
                || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')))
}

fn default_path(path_and_query: &str) -> String {
    let path = path_and_query.split('?').next().unwrap_or("/");
    if !path.starts_with('/') {
        return "/".to_owned();
    }
    match path.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(index) => path[..index].to_owned(),
    }
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Parse an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`).
///
/// Other `Expires` spellings are ignored rather than guessed at; an ignored
/// expiry is a session cookie, which is the safe direction for a client.
pub fn parse_http_date(value: &str) -> Option<SystemTime> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 6 || !parts[5].eq_ignore_ascii_case("GMT") {
        return None;
    }

    let day = parts[1].parse::<u32>().ok()?;
    let month = match parts[2].to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year = parts[3].parse::<i32>().ok()?;
    let mut clock = parts[4].split(':');
    let hour = clock.next()?.parse::<u32>().ok()?;
    let minute = clock.next()?.parse::<u32>().ok()?;
    let second = clock.next()?.parse::<u32>().ok()?;
    if clock.next().is_some() || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    let seconds =
        days as u64 * 86_400 + u64::from(hour) * 3_600 + u64::from(minute) * 60 + u64::from(second);
    Some(UNIX_EPOCH + Duration::from_secs(seconds))
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpResponse;

    fn response(set_cookies: &[&str]) -> HttpResponse {
        HttpResponse {
            status_code: 200,
            reason: "OK".into(),
            headers: set_cookies
                .iter()
                .map(|value| ("Set-Cookie".to_owned(), (*value).to_owned()))
                .collect(),
            body: Vec::new(),
        }
    }

    fn url(input: &str) -> Url {
        Url::parse(input).expect("url")
    }

    #[test]
    fn host_only_cookie_is_not_sent_to_a_subdomain() {
        let mut jar = CookieJar::new();
        let host = url("https://vpn.example.net/login");
        jar.store_from_response_at(
            &host,
            &response(&["DSID=abc123; Path=/; Secure"]),
            UNIX_EPOCH,
        );

        assert_eq!(
            jar.cookie_header_at(&host, UNIX_EPOCH).as_deref(),
            Some("DSID=abc123")
        );
        assert_eq!(
            jar.cookie_header_at(&url("https://sub.vpn.example.net/"), UNIX_EPOCH),
            None
        );
        assert_eq!(
            jar.cookie_header_at(&url("https://other.example.net/"), UNIX_EPOCH),
            None
        );
    }

    #[test]
    fn domain_cookie_applies_to_subdomains() {
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://vpn.example.net/"),
            &response(&["a=1; Domain=.example.net; Path=/"]),
            UNIX_EPOCH,
        );
        assert_eq!(
            jar.cookie_header_at(&url("https://sub.example.net/"), UNIX_EPOCH)
                .as_deref(),
            Some("a=1")
        );
        assert_eq!(
            jar.cookie_header_at(&url("https://example.net/"), UNIX_EPOCH)
                .as_deref(),
            Some("a=1")
        );
    }

    #[test]
    fn a_foreign_domain_attribute_is_refused() {
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://vpn.example.net/"),
            &response(&["a=1; Domain=example.org"]),
            UNIX_EPOCH,
        );
        assert!(jar.is_empty());
    }

    #[test]
    fn path_matching_follows_the_rfc_rules() {
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://example.net/dana-na/auth/login.cgi"),
            &response(&["a=1; Path=/dana-na"]),
            UNIX_EPOCH,
        );
        assert!(jar
            .cookie_header_at(&url("https://example.net/dana-na/auth/x"), UNIX_EPOCH)
            .is_some());
        assert!(jar
            .cookie_header_at(&url("https://example.net/dana-name"), UNIX_EPOCH)
            .is_none());
        assert!(jar
            .cookie_header_at(&url("https://example.net/"), UNIX_EPOCH)
            .is_none());
    }

    #[test]
    fn secure_cookies_are_only_sent_over_tls() {
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://example.net/"),
            &response(&["a=1; Secure"]),
            UNIX_EPOCH,
        );
        assert!(jar
            .cookie_header_at(&url("https://example.net/"), UNIX_EPOCH)
            .is_some());
        assert!(jar
            .cookie_header_at(&url("http://example.net/"), UNIX_EPOCH)
            .is_none());
    }

    #[test]
    fn max_age_controls_expiry_and_deletion() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://example.net/"),
            &response(&["a=1; Max-Age=60"]),
            now,
        );
        assert!(jar
            .cookie_header_at(&url("https://example.net/"), now + Duration::from_secs(59))
            .is_some());
        assert!(jar
            .cookie_header_at(&url("https://example.net/"), now + Duration::from_secs(60))
            .is_none());

        jar.store_from_response_at(
            &url("https://example.net/"),
            &response(&["a=2; Max-Age=0"]),
            now,
        );
        assert!(jar.is_empty());
    }

    #[test]
    fn expires_dates_are_parsed() {
        let parsed = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").expect("date");
        let expected = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(parsed, expected);

        let now = parsed + Duration::from_secs(1);
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://example.net/"),
            &response(&["a=1; Expires=Sun, 06 Nov 1994 08:49:37 GMT"]),
            now,
        );
        assert!(jar.is_empty());
    }

    #[test]
    fn unparsable_dates_leave_a_session_cookie() {
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://example.net/"),
            &response(&["a=1; Expires=not-a-date"]),
            UNIX_EPOCH,
        );
        assert_eq!(jar.len(), 1);
        assert!(jar
            .cookie_header_at(&url("https://example.net/"), UNIX_EPOCH)
            .is_some());
    }

    #[test]
    fn replacement_and_sending_order() {
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://example.net/a/b"),
            &response(&["short=1; Path=/"]),
            UNIX_EPOCH,
        );
        jar.store_from_response_at(
            &url("https://example.net/a/b"),
            &response(&["long=2; Path=/a"]),
            UNIX_EPOCH,
        );
        jar.store_from_response_at(
            &url("https://example.net/a/b"),
            &response(&["short=3; Path=/"]),
            UNIX_EPOCH,
        );

        let header = jar
            .cookie_header_at(&url("https://example.net/a/b"), UNIX_EPOCH)
            .expect("header");
        assert_eq!(header, "long=2; short=3");
    }

    #[test]
    fn host_matching_ignores_the_cookie_path_for_the_handshake() {
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://example.net/dana-na/auth/login.cgi"),
            &response(&["DSID=abc123; Path=/dana-na"]),
            UNIX_EPOCH,
        );
        assert_eq!(
            jar.cookie_header_at(&url("https://example.net/dana/js?prot=1&svc=4"), UNIX_EPOCH),
            None
        );
        assert_eq!(
            jar.cookie_header_for_host_at(
                &url("https://example.net/dana/js?prot=1&svc=4"),
                UNIX_EPOCH
            )
            .as_deref(),
            Some("DSID=abc123")
        );
    }

    #[test]
    fn diagnostics_report_metadata_and_never_the_value() {
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://example.net/dana-na/auth/login.cgi"),
            &response(&["DSID=super-secret-value; Path=/dana-na; Secure; HttpOnly"]),
            UNIX_EPOCH,
        );

        let login = jar.diagnostics_at(
            &url("https://example.net/dana-na/auth/login.cgi"),
            UNIX_EPOCH,
        );
        assert_eq!(login.jar_size, 1);
        assert_eq!(login.host_count, 1);
        assert_eq!(login.path_scoped_count, 1);
        assert!(!login.header_empty);
        assert_eq!(login.header_source, "host");
        assert_eq!(login.cookies[0].name, "DSID");
        assert_eq!(login.cookies[0].domain, "example.net");
        assert_eq!(login.cookies[0].path, "/dana-na");
        assert!(login.cookies[0].secure);
        assert!(login.cookies[0].host_applies);
        assert!(login.cookies[0].path_applies);

        // Outside the cookie path the host header still applies, which is why
        // the probe uses it.
        let outside = jar.diagnostics_at(&url("https://example.net/dana/nc/ncrun.cgi"), UNIX_EPOCH);
        assert_eq!(outside.host_count, 1);
        assert_eq!(outside.path_scoped_count, 0);
        assert!(!outside.header_empty);
        assert!(outside.cookies[0].host_applies);
        assert!(!outside.cookies[0].path_applies);

        let debug = format!("{outside:?}");
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("DSID"));
    }

    #[test]
    fn an_empty_jar_reports_an_empty_header() {
        let mut jar = CookieJar::new();
        let diagnostics = jar.diagnostics_at(&url("https://example.net/"), UNIX_EPOCH);
        assert_eq!(diagnostics.jar_size, 0);
        assert_eq!(diagnostics.host_count, 0);
        assert_eq!(diagnostics.path_scoped_count, 0);
        assert!(diagnostics.header_empty);
        assert!(diagnostics.cookies.is_empty());
    }

    #[test]
    fn debug_never_prints_cookie_values() {
        let mut jar = CookieJar::new();
        jar.store_from_response_at(
            &url("https://example.net/"),
            &response(&["secret-name=super-secret-value"]),
            UNIX_EPOCH,
        );
        let debug = format!("{jar:?} {jar:?}", jar = jar);
        assert!(!debug.contains("super-secret-value"));
        assert!(!debug.contains("secret-name"));
        assert!(debug.contains("CookieJar"));
    }
}
