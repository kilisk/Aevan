//! Stage 1 — credential-free auth probe.
//!
//! This stage opens TLS, follows redirects and reports exactly what the gateway
//! served. It never sends credentials, creates a device or changes routes. If
//! the final page contains no recognised form it says so: `form_shape: "none"`
//! plus the real redirect chain, rather than an invented login page.

use std::time::Duration;

use serde::Serialize;

use aevan_proto::{
    parse_forms, FollowedResponse, Form, HttpClient, HttpTransport, ProtoError, TlsObservation,
    TlsTransport, Url,
};

/// Default socket timeout for a probe.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default number of redirects to follow.
pub const DEFAULT_MAX_REDIRECTS: usize = 5;

/// The shape of the page the probe ended on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FormShape {
    /// No login or token form was found.
    None,
    /// A credential form (`frmLogin`, or a realm/password form).
    Login,
    /// A secondary-token form (`frmTotpToken` / `password#2`).
    Token,
}

/// Form facts extracted from the final page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormDetection {
    /// Overall page shape.
    pub shape: FormShape,
    /// Whether a credential form was found.
    pub login_form_present: bool,
    /// Whether a `realm` field was found.
    pub realm_field_present: bool,
    /// Whether a token field was found.
    pub token_field_present: bool,
    /// The credential form, when present.
    pub login_form: Option<Form>,
    /// The token form, when present.
    pub token_form: Option<Form>,
}

/// Detect the form shape of an HTML document without a DOM.
pub fn detect_forms(html: &str) -> FormDetection {
    let forms = parse_forms(html);
    let token_form = forms.iter().find(|form| form.has_token_field()).cloned();

    let classic_login = forms.iter().find(|form| form.is_login_form());
    let credential_form = classic_login
        .or_else(|| {
            forms.iter().find(|form| {
                !form.has_token_field() && form.has_realm_field() && form.has_password_field()
            })
        })
        .or_else(|| {
            forms
                .iter()
                .find(|form| !form.has_token_field() && form.has_realm_field())
        })
        .cloned();

    let login_form_present = classic_login.is_some() || credential_form.is_some();
    let realm_field_present = forms.iter().any(Form::has_realm_field);
    let token_field_present = token_form.is_some();

    let shape = if token_field_present {
        FormShape::Token
    } else if login_form_present {
        FormShape::Login
    } else {
        FormShape::None
    };

    FormDetection {
        shape,
        login_form_present,
        realm_field_present,
        token_field_present,
        login_form: credential_form,
        token_form,
    }
}

/// The typed result of stage 1.
///
/// `Debug` is not derived: the embedded forms can contain hidden session values
/// that must not reach a log.
#[derive(Clone, Serialize)]
pub struct AuthObservation {
    /// URL that was probed.
    pub url: String,
    /// TLS facts from the first connection.
    pub tls: TlsObservation,
    /// Every response in the redirect chain, in request order.
    pub redirects: Vec<aevan_proto::RedirectHop>,
    /// URL of the final response.
    pub final_url: String,
    /// Final status code.
    pub final_status: u16,
    /// Final reason phrase.
    pub final_reason: String,
    /// Detected form shape.
    pub form_shape: FormShape,
    /// Whether a credential form exists.
    pub login_form_present: bool,
    /// Whether a `realm` field exists.
    pub realm_field_present: bool,
    /// Whether a token field exists.
    pub token_field_present: bool,
    /// Resolved action of the credential form, if any.
    pub login_action: Option<String>,
    /// Whether the redirect hop limit stopped the probe.
    pub redirect_limit_reached: bool,
    #[serde(skip)]
    /// Credential form for stage 2. Never serialised.
    pub login_form: Option<Form>,
    #[serde(skip)]
    /// Token form, if the page is a token page. Never serialised.
    pub token_form: Option<Form>,
}

/// Stage 1 probe configuration.
#[derive(Debug, Clone, Copy)]
pub struct AuthProbe {
    timeout: Duration,
    max_redirects: usize,
}

impl Default for AuthProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthProbe {
    /// A probe with the default timeout and hop limit.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_redirects: DEFAULT_MAX_REDIRECTS,
        }
    }

    /// Override the socket timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the redirect hop limit.
    pub fn with_max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// Probe using an existing session, so the cookie jar can be reused by the
    /// login stage.
    pub fn run<T: HttpTransport>(
        &self,
        client: &mut HttpClient<T>,
        url: &Url,
    ) -> Result<AuthObservation, ProtoError> {
        let followed = client.get(url)?;
        self.observe(client, url, followed)
    }

    /// Probe with a fresh TLS session. Used by `aevan auth-probe`, which stops
    /// after this stage.
    pub fn probe(&self, url: &Url) -> Result<AuthObservation, ProtoError> {
        let mut client =
            HttpClient::with_max_redirects(TlsTransport::new(self.timeout), self.max_redirects);
        self.run(&mut client, url)
    }

    fn observe<T: HttpTransport>(
        &self,
        client: &HttpClient<T>,
        url: &Url,
        followed: FollowedResponse,
    ) -> Result<AuthObservation, ProtoError> {
        let tls = client
            .transport()
            .tls_observation()
            .cloned()
            .ok_or_else(|| ProtoError::Tls("transport reported no TLS observation".into()))?;
        let detection = detect_forms(&followed.body_text());
        let login_action = match &detection.login_form {
            Some(form) => Some(form.resolved_action(&followed.final_url)?.to_string()),
            None => None,
        };

        Ok(AuthObservation {
            url: url.to_string(),
            tls,
            redirects: followed.hops,
            final_url: followed.final_url.to_string(),
            final_status: followed.status_code,
            final_reason: followed.reason,
            form_shape: detection.shape,
            login_form_present: detection.login_form_present,
            realm_field_present: detection.realm_field_present,
            token_field_present: detection.token_field_present,
            login_action,
            redirect_limit_reached: followed.redirect_limit_reached,
            login_form: detection.login_form,
            token_form: detection.token_form,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevan_proto::{HttpResponse, RedirectHop, ScriptedTransport};

    const LOGIN_PAGE: &str = include_str!("../tests/fixtures/login-page.html");
    const TOKEN_PAGE: &str = include_str!("../tests/fixtures/token-page.html");
    const NO_FORM: &str = include_str!("../tests/fixtures/no-form.html");
    /// Synthetic welcome page whose form declares the relative action `login.cgi`.
    const EXAMPLE_STAFF_PAGE: &str = include_str!("../tests/fixtures/welcome-example.html");

    fn observation() -> TlsObservation {
        TlsObservation {
            protocol: "TLSv1_3".into(),
            chain: Vec::new(),
        }
    }

    fn html(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status_code: status,
            reason: "OK".into(),
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn detects_the_login_form_and_realm() {
        let detection = detect_forms(LOGIN_PAGE);
        assert_eq!(detection.shape, FormShape::Login);
        assert!(detection.login_form_present);
        assert!(detection.realm_field_present);
        assert!(!detection.token_field_present);
        assert_eq!(
            detection
                .login_form
                .as_ref()
                .and_then(|form| form.name_or_id()),
            Some("frmLogin")
        );
    }

    #[test]
    fn detects_the_token_page() {
        let detection = detect_forms(TOKEN_PAGE);
        assert_eq!(detection.shape, FormShape::Token);
        assert!(detection.token_field_present);
        assert!(!detection.login_form_present);
        let form = detection.token_form.expect("token form");
        assert_eq!(form.token_field_name().as_deref(), Some("password#2"));
    }

    #[test]
    fn a_page_without_a_form_is_reported_honestly() {
        let detection = detect_forms(NO_FORM);
        assert_eq!(detection.shape, FormShape::None);
        assert!(!detection.login_form_present);
        assert!(!detection.realm_field_present);
        assert!(!detection.token_field_present);
        assert!(detection.login_form.is_none());
    }

    #[test]
    fn example_staff_page_resolves_the_relative_login_action() {
        // A gateway may answer /staff with 302 to a per-realm "url_…" path
        // whose form declares the relative action "login.cgi". Resolution has to
        // be against the *final* URL, not the requested one.
        let redirect = HttpResponse {
            status_code: 302,
            reason: "Found".into(),
            headers: vec![(
                "Location".into(),
                "/dana-na/auth/url_ExampleRealm01/welcome.cgi".into(),
            )],
            body: Vec::new(),
        };
        let transport = ScriptedTransport::new([redirect, html(200, EXAMPLE_STAFF_PAGE)])
            .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let result = AuthProbe::new()
            .run(
                &mut client,
                &Url::parse("https://vpn.example.com/staff").expect("url"),
            )
            .expect("probe");

        assert_eq!(result.redirects.len(), 2);
        assert_eq!(result.final_status, 200);
        assert_eq!(result.form_shape, FormShape::Login);
        assert!(result.realm_field_present);
        assert!(!result.token_field_present);
        assert_eq!(
            result.login_action.as_deref(),
            Some("https://vpn.example.com/dana-na/auth/url_ExampleRealm01/login.cgi")
        );
    }

    #[test]
    fn probe_records_every_redirect_hop_and_final_page() {
        let redirect = HttpResponse {
            status_code: 302,
            reason: "Found".into(),
            headers: vec![("Location".into(), "/example_realm/login".into())],
            body: Vec::new(),
        };
        let transport = ScriptedTransport::new([redirect, html(200, LOGIN_PAGE)])
            .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let probe = AuthProbe::new();
        let result = probe
            .run(
                &mut client,
                &Url::parse("https://vpn.example.net/").expect("url"),
            )
            .expect("probe");

        assert_eq!(result.redirects.len(), 2);
        assert_eq!(result.redirects[0].status_code, 302);
        assert_eq!(
            result.redirects[0].location.as_deref(),
            Some("/example_realm/login")
        );
        assert_eq!(
            result.final_url,
            "https://vpn.example.net/example_realm/login"
        );
        assert_eq!(result.form_shape, FormShape::Login);
        assert_eq!(
            result.login_action.as_deref(),
            Some("https://vpn.example.net/example_realm/login.cgi")
        );
    }

    #[test]
    fn a_404_shell_reports_none_not_an_invented_login() {
        let transport =
            ScriptedTransport::new([html(404, NO_FORM)]).with_observation(observation());
        let mut client = HttpClient::new(transport);
        let probe = AuthProbe::new();
        let result = probe
            .run(
                &mut client,
                &Url::parse("https://vpn.example.net/").expect("url"),
            )
            .expect("probe");

        assert_eq!(result.form_shape, FormShape::None);
        assert_eq!(result.final_status, 404);
        assert_eq!(result.redirects.len(), 1);
        assert_eq!(
            result.redirects[0],
            RedirectHop {
                url: "https://vpn.example.net/".into(),
                status_code: 404,
                reason: "OK".into(),
                location: None,
            }
        );
    }
}
