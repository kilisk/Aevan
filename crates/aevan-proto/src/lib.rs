#![deny(unsafe_code)]
//! Protocol building blocks for the Network Connect transport.
//!
//! Stage 1 and 2 building blocks: URL parsing, a TLS
//! handshake that reports the presented chain, HTTP request/response handling,
//! an RFC 6265 cookie jar, a redirect-following `GET`, a `POST` helper and a
//! small HTML form scraper. The NCP configuration parser lives in `aevan-nc`.
//!
//! Nothing in this crate logs, stores or forwards credentials. Request and
//! response `Debug` implementations omit bodies and redact header values.
//! Cookies are only ever emitted into a request line, never printed.

pub mod client;
pub mod cookies;
pub mod error;
pub mod html;
pub mod http;
pub mod realm;
pub mod tls;
pub mod url;

pub use client::{
    FollowedResponse, HttpClient, HttpTransport, RedirectHop, ScriptedTransport, TlsTransport,
    DEFAULT_MAX_REDIRECTS,
};
pub use cookies::{parse_http_date, Cookie, CookieDiagnostics, CookieInfo, CookieJar};
pub use error::ProtoError;
pub use html::{find_input, parse_forms, Form, FormInput};
pub use http::{build_get_request, build_post_request, parse_response, HttpRequest, HttpResponse};
pub use realm::{
    detect_realm, detect_realm_with, detect_realm_with_timeout, realm_from_page, RealmError,
    DEFAULT_REALM_TIMEOUT,
};
pub use tls::{inspect_https, CertInfo, Inspection, RawTls, TlsObservation};
pub use url::Url;
