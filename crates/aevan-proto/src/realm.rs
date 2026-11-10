//! Credential-free realm discovery.
//!
//! A Network Connect gateway advertises the authentication realm on its sign-in
//! page. The vendor client never asks for it: it follows the portal redirect to
//! `/dana-na/auth/url_<realm>/welcome.cgi` and submits the hidden `realm` input
//! the page carries. This module performs the same single unauthenticated `GET`
//! and extracts that value, falling back to the `url_<realm>` path segment.
//!
//! Detection never sends a credential, never issues a `POST` and therefore
//! never consumes a login attempt.

use std::time::Duration;

use crate::client::{HttpClient, HttpTransport, TlsTransport, DEFAULT_MAX_REDIRECTS};
use crate::error::ProtoError;
use crate::html::{parse_forms, Form};
use crate::url::Url;

/// Timeout for one realm-detection request.
pub const DEFAULT_REALM_TIMEOUT: Duration = Duration::from_secs(10);

/// Why realm discovery did not produce a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RealmError {
    /// The portal answered, but neither the sign-in form nor its URL named a
    /// realm.
    #[error("the sign-in page did not advertise a realm; pass --realm <value>")]
    NotAdvertised {
        /// URL of the final response, retained for diagnostics.
        final_url: String,
    },
    /// The request itself failed before a page could be inspected.
    #[error("realm detection failed: {0}")]
    Transport(String),
}

/// Discover the realm for `url` with one credential-free, redirect-following
/// `GET`.
pub fn detect_realm(url: &Url) -> Result<String, RealmError> {
    detect_realm_with_timeout(url, DEFAULT_REALM_TIMEOUT)
}

/// Discover the realm for `url`, overriding the socket timeout.
pub fn detect_realm_with_timeout(url: &Url, timeout: Duration) -> Result<String, RealmError> {
    let mut client =
        HttpClient::with_max_redirects(TlsTransport::new(timeout), DEFAULT_MAX_REDIRECTS);
    detect_realm_with(&mut client, url)
}

/// Discover the realm using an existing client, which makes the network path
/// testable without a socket.
pub fn detect_realm_with<T: HttpTransport>(
    client: &mut HttpClient<T>,
    url: &Url,
) -> Result<String, RealmError> {
    let followed = client
        .get(url)
        .map_err(|error: ProtoError| RealmError::Transport(error.to_string()))?;

    realm_from_page(&followed.body_text(), &followed.final_url).ok_or_else(|| {
        RealmError::NotAdvertised {
            final_url: followed.final_url.to_string(),
        }
    })
}

/// Extract a realm from a final page and its URL.
///
/// The hidden `realm` input in the sign-in form wins. When no form advertises
/// one, the `/url_<realm>/` segment of the final URL is used.
pub fn realm_from_page(html: &str, final_url: &Url) -> Option<String> {
    let forms = parse_forms(html);

    forms
        .iter()
        .find(|form| form.is_login_form())
        .and_then(hidden_realm)
        .or_else(|| {
            forms
                .iter()
                .filter(|form| form.has_password_field() || form.has_realm_field())
                .find_map(hidden_realm)
        })
        .or_else(|| forms.iter().find_map(hidden_realm))
        .or_else(|| realm_from_final_url(final_url))
}

fn hidden_realm(form: &Form) -> Option<String> {
    form.inputs
        .iter()
        .find(|input| {
            input.is_hidden()
                && input
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case("realm"))
        })
        .and_then(|input| input.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn realm_from_final_url(url: &Url) -> Option<String> {
    let path = url.path_and_query.split('?').next().unwrap_or_default();
    path.split('/')
        .find_map(|segment| segment.strip_prefix("url_"))
        .map(str::trim)
        .filter(|realm| !realm.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ScriptedTransport;
    use crate::http::HttpResponse;

    const HIDDEN_REALM_PAGE: &str = include_str!("../tests/fixtures/welcome-realm.html");
    const URL_ONLY_PAGE: &str = include_str!("../tests/fixtures/welcome-url-only.html");
    const NO_REALM_PAGE: &str = include_str!("../tests/fixtures/welcome-no-realm.html");

    fn html(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status_code: status,
            reason: "OK".into(),
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn redirect(location: &str) -> HttpResponse {
        HttpResponse {
            status_code: 302,
            reason: "Found".into(),
            headers: vec![("Location".into(), location.to_owned())],
            body: Vec::new(),
        }
    }

    #[test]
    fn a_hidden_realm_input_is_used_before_the_url() {
        let transport = ScriptedTransport::new([
            redirect("/dana-na/auth/url_other_realm/welcome.cgi"),
            html(200, HIDDEN_REALM_PAGE),
        ]);
        let mut client = HttpClient::new(transport);
        let url = Url::parse("https://vpn.example.com/staff").expect("url");

        let realm = detect_realm_with(&mut client, &url).expect("realm");
        assert_eq!(realm, "mygovnet_staff");

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 2);
        assert!(
            requests.iter().all(|request| request.method == "GET"),
            "detection must never POST a credential"
        );
    }

    #[test]
    fn the_url_segment_is_the_fallback() {
        let transport = ScriptedTransport::new([
            redirect("/dana-na/auth/url_mygovnet_staff/welcome.cgi"),
            html(200, URL_ONLY_PAGE),
        ]);
        let mut client = HttpClient::new(transport);
        let url = Url::parse("https://vpn.example.com/staff").expect("url");

        let realm = detect_realm_with(&mut client, &url).expect("realm");
        assert_eq!(realm, "mygovnet_staff");
    }

    #[test]
    fn a_page_with_neither_source_is_a_typed_error() {
        let transport = ScriptedTransport::new([
            redirect("/dana-na/auth/welcome.cgi"),
            html(200, NO_REALM_PAGE),
        ]);
        let mut client = HttpClient::new(transport);
        let url = Url::parse("https://vpn.example.com/staff").expect("url");

        let error = detect_realm_with(&mut client, &url).expect_err("must not invent a realm");
        assert!(matches!(error, RealmError::NotAdvertised { .. }));
        assert!(error.to_string().contains("did not advertise a realm"));
        assert!(error.to_string().contains("pass --realm <value>"));
    }
}
