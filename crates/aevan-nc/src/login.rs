//! Stage 2 — one credential POST and its classification.
//!
//! The types here deliberately contain no retry loop, no fallback host and no
//! profile switching. [`LoginRequest::submit`] performs exactly one POST.
//! [`TokenRequest`] is the single continuation for a token challenge; the
//! caller decides whether to use it and must not call either type in a loop.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use aevan_core::local_utc_offset_minutes;
use aevan_proto::{
    parse_forms, Form, HttpClient, HttpResponse, HttpTransport, ProtoError, Url,
    DEFAULT_MAX_REDIRECTS,
};

/// Form content type used by the gateway.
pub const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// Value the gateway confirmation page submits for `btnContinue`.
pub const CONTINUE_VALUE: &str = "Continue the session";

const CONTINUATION_MARKER: &str = "user-confirm";
const DASHBOARD_MARKERS: &[&str] = &["frmdashboard", "dashboard"];

const REJECTION_MARKERS: &[&str] = &[
    "authentication failed",
    "login failed",
    "invalid username or password",
    "incorrect password",
    "access denied",
    "invalid credentials",
    "authentication error",
    "account is locked",
    "user is locked",
    "username or password is incorrect",
    "the username or password you entered is incorrect",
];

const SUCCESS_MARKERS: &[&str] = &[
    "login successful",
    "signed in successfully",
    "you are now signed in",
    "successfully signed in",
];

/// Per-attempt values the gateway login form needs besides the credentials.
///
/// The reference implementation builds its POST from both the credential triple
/// and a handful of anti-cache/telemetry fields. Tests inject these explicitly
/// so a body assertion can be deterministic; [`LoginContext::fresh`] is the
/// live path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginContext {
    /// Fresh per-attempt `xsauth` nonce.
    pub xsauth: String,
    /// Local UTC offset in minutes (for example `480` for UTC+8).
    pub tz_offset_minutes: i32,
    /// Current Unix time in seconds.
    pub clienttime: i64,
    /// Whether this attempt resumes an existing gateway session.
    pub resuming_session: bool,
}

impl LoginContext {
    /// Build a context for a live attempt.
    ///
    /// There is no direct RNG dependency in this crate and the workspace
    /// forbids adding one, so `xsauth` is derived from the nanosecond clock,
    /// the process id and a per-process counter. This is not a cryptographic
    /// RNG; the gateway's login form expects `xsauth` as a request/anti-cache
    /// nonce, and the gateway issues the actual session cookie. Callers that need a
    /// deterministic body use [`LoginContext::new`] instead.
    pub fn fresh() -> Self {
        Self {
            xsauth: random_token(),
            tz_offset_minutes: local_utc_offset_minutes().unwrap_or(0),
            clienttime: unix_seconds(),
            resuming_session: false,
        }
    }

    /// Explicit values, for tests and callers with their own clock and nonce.
    pub fn new(xsauth: impl Into<String>, tz_offset_minutes: i32, clienttime: i64) -> Self {
        Self {
            xsauth: xsauth.into(),
            tz_offset_minutes,
            clienttime,
            resuming_session: false,
        }
    }

    /// Mark this attempt as resuming an existing session, which makes the
    /// credential POST carry `btnContinue`.
    pub fn resuming_session(mut self) -> Self {
        self.resuming_session = true;
        self
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn random_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let pid = u64::from(std::process::id());
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut value = nanos ^ pid.rotate_left(32) ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^= value >> 31;
    format!("{value:016x}")
}

/// A credential POST, built from the sign-in form.
pub struct LoginRequest {
    action: Url,
    realm: String,
    username: String,
    password: Zeroizing<String>,
    hidden: Vec<(String, String)>,
    username_field: String,
    password_field: String,
    realm_field: String,
    context: LoginContext,
    btn_continue: bool,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("action", &self.action.to_string())
            .field("realm", &self.realm)
            .field("hidden_fields", &self.hidden.len())
            .finish()
    }
}

impl LoginRequest {
    /// Build a request from a detected credential form.
    pub fn from_form(
        form: &Form,
        base: &Url,
        realm: &str,
        username: &str,
        password: impl Into<String>,
    ) -> Result<Self, ProtoError> {
        Self::from_form_with_context(form, base, realm, username, password, LoginContext::fresh())
    }

    /// Build a request with explicit per-attempt values.
    pub fn from_form_with_context(
        form: &Form,
        base: &Url,
        realm: &str,
        username: &str,
        password: impl Into<String>,
        context: LoginContext,
    ) -> Result<Self, ProtoError> {
        let action = form.resolved_action(base)?;
        let username_field = form
            .input_name(&["username", "user", "userid", "j_username"])
            .unwrap_or_else(|| "username".to_owned());
        let password_field = form
            .input_name(&["password", "passwd", "j_password"])
            .unwrap_or_else(|| "password".to_owned());
        let realm_field = form
            .input_name(&["realm"])
            .unwrap_or_else(|| "realm".to_owned());
        let hidden = carried_hidden_fields(
            form,
            &[
                username_field.as_str(),
                password_field.as_str(),
                realm_field.as_str(),
            ],
        );
        let btn_continue = context.resuming_session || is_confirmation_form(form);

        Ok(Self {
            action,
            realm: realm.to_owned(),
            username: username.to_owned(),
            password: Zeroizing::new(password.into()),
            hidden,
            username_field,
            password_field,
            realm_field,
            context,
            btn_continue,
        })
    }

    /// Build a minimal request without a discovered form, for tests and for
    /// callers that already know the endpoint.
    pub fn new(action: Url, realm: &str, username: &str, password: impl Into<String>) -> Self {
        Self::new_with_context(action, realm, username, password, LoginContext::fresh())
    }

    /// Build a minimal request with explicit per-attempt values.
    pub fn new_with_context(
        action: Url,
        realm: &str,
        username: &str,
        password: impl Into<String>,
        context: LoginContext,
    ) -> Self {
        let btn_continue = context.resuming_session;
        Self {
            action,
            realm: realm.to_owned(),
            username: username.to_owned(),
            password: Zeroizing::new(password.into()),
            hidden: Vec::new(),
            username_field: "username".to_owned(),
            password_field: "password".to_owned(),
            realm_field: "realm".to_owned(),
            context,
            btn_continue,
        }
    }

    /// Target URL.
    pub fn action(&self) -> &Url {
        &self.action
    }

    /// Build the percent-encoded form body. The result is secret.
    pub fn body(&self) -> Zeroizing<String> {
        Zeroizing::new(form_urlencode(&self.fields()))
    }

    /// Names of the body fields in wire order, never their values.
    ///
    /// This is what the diagnostic dump records; in particular the `xsauth`
    /// value is not included.
    pub fn field_names(&self) -> Vec<String> {
        self.fields().into_iter().map(|(name, _)| name).collect()
    }

    fn fields(&self) -> Vec<(String, String)> {
        let mut fields = Vec::with_capacity(9 + self.hidden.len());
        fields.push((self.username_field.clone(), self.username.clone()));
        fields.push((self.password_field.clone(), self.password.to_string()));
        fields.push((self.realm_field.clone(), self.realm.clone()));
        fields.push(("xsauth".to_owned(), self.context.xsauth.clone()));
        fields.push((
            "tz_offset".to_owned(),
            self.context.tz_offset_minutes.to_string(),
        ));
        fields.push(("clienttime".to_owned(), self.context.clienttime.to_string()));
        fields.push(("url".to_owned(), String::new()));
        fields.push(("activex_enabled".to_owned(), "0".to_owned()));
        fields.push(("java_enabled".to_owned(), "0".to_owned()));
        if self.btn_continue {
            fields.push(("btnContinue".to_owned(), CONTINUE_VALUE.to_owned()));
        }

        // Carried hidden fields never override the explicitly built ones.
        for (name, value) in &self.hidden {
            if fields
                .iter()
                .any(|(existing, _)| existing.eq_ignore_ascii_case(name))
            {
                continue;
            }
            fields.push((name.clone(), value.clone()));
        }
        fields
    }

    /// Perform exactly one credential POST and classify the response.
    pub fn submit<T: HttpTransport>(
        &self,
        client: &mut HttpClient<T>,
    ) -> Result<LoginOutcome, ProtoError> {
        Ok(self.submit_with_response(client)?.outcome)
    }

    /// Perform exactly one credential POST, keeping the raw response for a dump.
    pub fn submit_with_response<T: HttpTransport>(
        &self,
        client: &mut HttpClient<T>,
    ) -> Result<LoginSubmission, ProtoError> {
        let body = self.body();
        tracing::debug!(
            path = %self.action.path_and_query.split('?').next().unwrap_or("/"),
            "submitting login form"
        );
        let response = client.post(&self.action, FORM_CONTENT_TYPE, body.as_bytes())?;
        let outcome = LoginOutcome::classify(&response, &self.action);
        Ok(LoginSubmission {
            outcome,
            response,
            request_field_names: self.field_names(),
        })
    }
}

/// A detected token challenge.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenChallenge {
    /// Form action.
    pub action: Url,
    /// Hidden form fields to preserve.
    pub hidden: Vec<(String, String)>,
    /// Input name that carries the token.
    pub token_field: String,
}

impl fmt::Debug for TokenChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenChallenge")
            .field("action", &self.action.to_string())
            .field("hidden_fields", &self.hidden.len())
            .field("token_field", &self.token_field)
            .finish()
    }
}

impl TokenChallenge {
    fn from_form(form: &Form, base: &Url) -> Result<Self, ProtoError> {
        let action = form.resolved_action(base)?;
        let token_field = form
            .token_field_name()
            .unwrap_or_else(|| "password#2".to_owned());
        let hidden = carried_fields(form, &["password", "passwd", "token", &token_field]);
        Ok(Self {
            action,
            hidden,
            token_field,
        })
    }
}

/// One continuation POST for a token challenge.
pub struct TokenRequest {
    action: Url,
    hidden: Vec<(String, String)>,
    token_field: String,
    token: Zeroizing<String>,
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest")
            .field("action", &self.action.to_string())
            .field("hidden_fields", &self.hidden.len())
            .field("token_field", &self.token_field)
            .finish()
    }
}

impl TokenRequest {
    /// Build a token continuation from a challenge and a token value.
    pub fn from_challenge(challenge: &TokenChallenge, token: impl Into<String>) -> Self {
        Self {
            action: challenge.action.clone(),
            hidden: challenge.hidden.clone(),
            token_field: challenge.token_field.clone(),
            token: Zeroizing::new(token.into()),
        }
    }

    /// Target URL.
    pub fn action(&self) -> &Url {
        &self.action
    }

    /// Build the percent-encoded form body. The result is secret.
    pub fn body(&self) -> Zeroizing<String> {
        let mut fields = self.hidden.clone();
        fields.push((self.token_field.clone(), self.token.to_string()));
        Zeroizing::new(form_urlencode(&fields))
    }

    /// Perform exactly one token POST and classify the response.
    pub fn submit<T: HttpTransport>(
        &self,
        client: &mut HttpClient<T>,
    ) -> Result<LoginOutcome, ProtoError> {
        Ok(self.submit_with_response(client)?.outcome)
    }

    /// Perform exactly one token POST, keeping the raw response for a dump.
    pub fn submit_with_response<T: HttpTransport>(
        &self,
        client: &mut HttpClient<T>,
    ) -> Result<LoginSubmission, ProtoError> {
        let body = self.body();
        tracing::debug!(
            path = %self.action.path_and_query.split('?').next().unwrap_or("/"),
            "submitting token form"
        );
        let response = client.post(&self.action, FORM_CONTENT_TYPE, body.as_bytes())?;
        let outcome = LoginOutcome::classify(&response, &self.action);
        let mut request_field_names: Vec<String> =
            self.hidden.iter().map(|(name, _)| name.clone()).collect();
        request_field_names.push(self.token_field.clone());
        Ok(LoginSubmission {
            outcome,
            response,
            request_field_names,
        })
    }
}

/// The gateway's "you already have a session; confirm to continue" step.
///
/// The continuation is part of the same authentication exchange, not a retry.
/// It never carries credentials and is not counted as an authentication
/// attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct ContinuationChallenge {
    /// Redirect target, when the gateway used a redirect. `None` means the
    /// continuation form was served directly in a 200 response.
    pub location: Option<String>,
    /// URL of a directly served confirmation page, when `location` is `None`.
    pub page_url: Option<String>,
    /// HTML of a directly served confirmation page, when `location` is `None`.
    ///
    /// The page can contain hidden session state; `Debug` records only its
    /// length.
    pub page_html: Option<String>,
}

impl ContinuationChallenge {
    fn redirect(location: &str) -> Self {
        Self {
            location: Some(location.to_owned()),
            page_url: None,
            page_html: None,
        }
    }

    fn served(url: &Url, html: String) -> Self {
        Self {
            location: None,
            page_url: Some(url.to_string()),
            page_html: Some(html),
        }
    }
}

impl fmt::Debug for ContinuationChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationChallenge")
            .field("has_location", &self.location.is_some())
            .field("has_page", &self.page_html.is_some())
            .finish()
    }
}

/// One continuation form and the exact fields it will submit.
#[derive(Clone, PartialEq, Eq)]
pub struct ContinuationRequest {
    action: Url,
    fields: Vec<(String, String)>,
}

impl fmt::Debug for ContinuationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationRequest")
            .field("action", &self.action.to_string())
            .field("fields", &self.fields.len())
            .finish()
    }
}

impl ContinuationRequest {
    /// Find the continuation form in a user-confirm page.
    ///
    /// A page with exactly one form uses it. With several forms, a form on the
    /// same host that carries a submit/button or a continue/confirm-style
    /// hidden field wins; credential and token forms are never selected.
    pub fn from_page(html: &str, page: &Url) -> Result<Option<Self>, ProtoError> {
        let forms = parse_forms(html);
        let Some(form) = select_continuation_form(&forms, page) else {
            return Ok(None);
        };

        let action = form.resolved_action(page)?;
        let confirmation = is_confirmation_form(form);
        let mut fields = Vec::new();
        for input in &form.inputs {
            if input.disabled {
                continue;
            }
            let Some(name) = input.name.as_ref() else {
                continue;
            };
            let submit = !confirmation && (input.type_is("submit") || input.type_is("button"));
            if input.is_hidden() || submit {
                fields.push((name.clone(), input.value.clone().unwrap_or_default()));
            }
        }

        if confirmation {
            // The gateway confirmation page answers with `btnContinue` plus its
            // hidden `FormDataStr`; `btnCancel` must not be submitted.
            let value = form
                .inputs
                .iter()
                .find(|input| {
                    input
                        .name
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case("btnContinue"))
                })
                .and_then(|input| input.value.clone())
                .unwrap_or_else(|| CONTINUE_VALUE.to_owned());
            fields.retain(|(name, _)| !name.eq_ignore_ascii_case("btnContinue"));
            fields.push(("btnContinue".to_owned(), value));
        }

        Ok(Some(Self { action, fields }))
    }

    /// Target URL.
    pub fn action(&self) -> &Url {
        &self.action
    }

    /// Build the percent-encoded form body.
    pub fn body(&self) -> Zeroizing<String> {
        Zeroizing::new(form_urlencode(&self.fields))
    }

    /// Perform exactly one continuation POST and classify the response.
    pub fn submit_with_response<T: HttpTransport>(
        &self,
        client: &mut HttpClient<T>,
    ) -> Result<LoginSubmission, ProtoError> {
        let body = self.body();
        tracing::debug!(
            path = %self.action.path_and_query.split('?').next().unwrap_or("/"),
            "submitting user-confirm continuation form"
        );
        let response = client.post(&self.action, FORM_CONTENT_TYPE, body.as_bytes())?;
        let outcome = LoginOutcome::classify(&response, &self.action);
        Ok(LoginSubmission {
            outcome,
            response,
            request_field_names: self.fields.iter().map(|(name, _)| name.clone()).collect(),
        })
    }
}

/// One hop of the user-confirm exchange, kept for the diagnostic dump.
#[derive(Clone, PartialEq, Eq)]
pub struct ContinuationHop {
    /// Requested URL.
    pub url: String,
    /// Response status.
    pub status_code: u16,
    /// Response reason.
    pub reason: String,
    /// Response headers, in wire order. May contain `Set-Cookie`.
    pub headers: Vec<(String, String)>,
}

impl fmt::Debug for ContinuationHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationHop")
            .field("url", &self.url)
            .field("status_code", &self.status_code)
            .field("reason", &self.reason)
            .field("header_count", &self.headers.len())
            .finish()
    }
}

/// The complete user-confirm exchange for a dump.
#[derive(Clone, PartialEq, Eq)]
pub struct ContinuationObservation {
    /// Every hop: the GET chain followed by the continuation POST response.
    pub hops: Vec<ContinuationHop>,
    /// The served user-confirm HTML, if any.
    pub page_html: Option<String>,
}

impl fmt::Debug for ContinuationObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationObservation")
            .field("hops", &self.hops.len())
            .field("page_html", &self.page_html.as_ref().map(String::len))
            .finish()
    }
}

/// The continuation POST's final response and the exchange that produced it.
#[derive(Debug)]
pub struct ContinuationExchange {
    /// Classified final response.
    pub submission: LoginSubmission,
    /// Dump-safe exchange facts.
    pub observation: ContinuationObservation,
}

/// Errors from the single user-confirm continuation.
#[derive(Debug, thiserror::Error)]
pub enum ContinuationError {
    /// Network or protocol failure while fetching or submitting the form.
    #[error("user-confirm continuation: {0}")]
    Transport(#[from] ProtoError),
    /// The page did not contain a usable continuation form.
    #[error("the user-confirm page served no continuation form")]
    NoForm,
    /// The gateway asked for another user-confirm step.
    #[error("the gateway asked for a second user-confirm page; refusing to continue")]
    LoopDetected,
}

/// Complete the user-confirm step with at most one POST.
///
/// The GET chain and the POST response are recorded for the dump. A second
/// user-confirm response is [`ContinuationError::LoopDetected`], never another
/// POST. This function does not touch credentials.
pub fn complete_continuation<T: HttpTransport>(
    client: &mut HttpClient<T>,
    challenge: &ContinuationChallenge,
    base: &Url,
) -> Result<ContinuationExchange, ContinuationError> {
    let mut hops = Vec::new();
    let (current, html) = if let Some(page_html) = &challenge.page_html {
        // A 200 credential response already served the confirmation form; do
        // not spend another GET on it.
        let current = match challenge.page_url.as_deref() {
            Some(url) => Url::parse(url)?,
            None => base.clone(),
        };
        (current, page_html.clone())
    } else {
        let mut current = match challenge.location.as_deref() {
            Some(location) => base.join(location)?,
            None => base.clone(),
        };
        let mut followed = 0;
        let final_response = loop {
            let response = client.get_once(&current)?;
            hops.push(ContinuationHop {
                url: current.to_string(),
                status_code: response.status_code,
                reason: response.reason.clone(),
                headers: response.headers.clone(),
            });

            let location = response.location().map(str::to_owned);
            if response.is_redirect() && followed < DEFAULT_MAX_REDIRECTS {
                if let Some(location) = location {
                    current = current.join(&location)?;
                    followed += 1;
                    continue;
                }
            }
            break response;
        };
        (current, final_response.body_text())
    };

    let request =
        ContinuationRequest::from_page(&html, &current)?.ok_or(ContinuationError::NoForm)?;
    let submission = request.submit_with_response(client)?;
    hops.push(ContinuationHop {
        url: request.action().to_string(),
        status_code: submission.response.status_code,
        reason: submission.response.reason.clone(),
        headers: submission.response.headers.clone(),
    });

    if matches!(
        submission.outcome,
        LoginOutcome::ContinuationRequired { .. }
    ) {
        return Err(ContinuationError::LoopDetected);
    }

    Ok(ContinuationExchange {
        submission,
        observation: ContinuationObservation {
            hops,
            page_html: (!html.is_empty()).then_some(html),
        },
    })
}

/// One authentication POST together with the response that produced it.
///
/// The response can contain `Set-Cookie` headers; it is kept only so a caller
/// can write a redacted diagnostic dump. Its `Debug` never prints header values.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginSubmission {
    /// Classified outcome.
    pub outcome: LoginOutcome,
    /// Raw response.
    pub response: HttpResponse,
    /// Submitted field names in wire order, never values.
    pub request_field_names: Vec<String>,
}

impl fmt::Debug for LoginSubmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSubmission")
            .field("outcome", &self.outcome)
            .field("status_code", &self.response.status_code)
            .field("header_count", &self.response.headers.len())
            .field("body_bytes", &self.response.body.len())
            .field("request_field_names", &self.request_field_names)
            .finish()
    }
}

/// The classified result of one authentication POST.
#[derive(Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// The gateway accepted the credentials.
    Success {
        /// Status code.
        status_code: u16,
        /// Post-login redirect, if the gateway used one.
        location: Option<String>,
    },
    /// A secondary token is required.
    TokenRequired {
        /// Status code.
        status_code: u16,
        /// The token form to submit.
        challenge: TokenChallenge,
    },
    /// The gateway has an existing session that must be confirmed.
    ContinuationRequired {
        /// Status code.
        status_code: u16,
        /// The continuation form to fetch and submit once.
        challenge: ContinuationChallenge,
    },
    /// The gateway rejected the credentials.
    Rejected {
        /// Status code.
        status_code: u16,
        /// A fixed, non-secret reason.
        reason: String,
    },
}

impl fmt::Debug for LoginOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success {
                status_code,
                location,
            } => f
                .debug_struct("Success")
                .field("status_code", status_code)
                .field("has_location", &location.is_some())
                .finish(),
            Self::TokenRequired {
                status_code,
                challenge,
            } => f
                .debug_struct("TokenRequired")
                .field("status_code", status_code)
                .field("challenge", challenge)
                .finish(),
            Self::ContinuationRequired {
                status_code,
                challenge,
            } => f
                .debug_struct("ContinuationRequired")
                .field("status_code", status_code)
                .field("challenge", challenge)
                .finish(),
            Self::Rejected {
                status_code,
                reason,
            } => f
                .debug_struct("Rejected")
                .field("status_code", status_code)
                .field("reason", reason)
                .finish(),
        }
    }
}

impl LoginOutcome {
    /// Classify an HTTP response using only its status, headers and body.
    pub fn classify(response: &HttpResponse, base: &Url) -> Self {
        let status_code = response.status_code;
        let body = response.body_text();
        let lower = body.to_ascii_lowercase();
        let forms = parse_forms(&body);
        let dashboard = has_dashboard_marker(&lower);

        if status_code == 401
            || status_code == 403
            || REJECTION_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
        {
            return Self::Rejected {
                status_code,
                reason: "gateway rejected the credentials".to_owned(),
            };
        }

        if let Some(form) = forms.iter().find(|form| form.has_token_field()) {
            if let Ok(challenge) = TokenChallenge::from_form(form, base) {
                return Self::TokenRequired {
                    status_code,
                    challenge,
                };
            }
        }

        if (300..400).contains(&status_code) {
            if let Some(location) = response.header("location") {
                if is_user_confirm_location(location) {
                    return Self::ContinuationRequired {
                        status_code,
                        challenge: ContinuationChallenge::redirect(location),
                    };
                }
            }
        }

        if status_code == 200
            && !dashboard
            && forms
                .iter()
                .any(|form| is_confirmation_form(form) || looks_like_continuation_form(form))
        {
            return Self::ContinuationRequired {
                status_code,
                challenge: ContinuationChallenge::served(base, body),
            };
        }

        let session_cookie = issued_session_cookie(response);

        if (300..400).contains(&status_code) {
            let Some(location) = response.header("location") else {
                return Self::Rejected {
                    status_code,
                    reason: "redirect without a Location header".to_owned(),
                };
            };
            if !is_signin_location(location) || session_cookie {
                return Self::Success {
                    status_code,
                    location: Some(location.to_owned()),
                };
            }
            return Self::Rejected {
                status_code,
                reason: "bounced back to the sign-in page".to_owned(),
            };
        }

        if (200..300).contains(&status_code) {
            if session_cookie {
                return Self::Success {
                    status_code,
                    location: None,
                };
            }
            let signin = looks_like_signin_page(&forms, &lower);
            if dashboard || (SUCCESS_MARKERS.iter().any(|marker| lower.contains(marker)) && !signin)
            {
                return Self::Success {
                    status_code,
                    location: None,
                };
            }
            return Self::Rejected {
                status_code,
                reason: if signin {
                    "bounced back to the sign-in page".to_owned()
                } else {
                    "no session cookie issued".to_owned()
                },
            };
        }

        Self::Rejected {
            status_code,
            reason: format!("unexpected HTTP {status_code} without a session cookie"),
        }
    }
}

fn has_dashboard_marker(lower: &str) -> bool {
    DASHBOARD_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Whether the login response itself issued a DSID or DSSIGNIN cookie.
fn issued_session_cookie(response: &HttpResponse) -> bool {
    response.header_all("set-cookie").any(|header| {
        let pair = header.split(';').next().unwrap_or_default();
        let Some((name, _)) = pair.split_once('=') else {
            return false;
        };
        let name = name.trim();
        name.eq_ignore_ascii_case("DSID") || name.eq_ignore_ascii_case("DSSIGNIN")
    })
}

/// Whether a redirect target is a sign-in/auth page rather than a dashboard.
fn is_signin_location(location: &str) -> bool {
    let lower = location
        .to_ascii_lowercase()
        .replace("%2d", "-")
        .replace("%2f", "/");
    let path = lower.split('?').next().unwrap_or_default();
    path.contains("welcome.cgi") || path.contains("login.cgi") || path.contains("/dana-na/auth/")
}

fn looks_like_signin_page(forms: &[Form], lower: &str) -> bool {
    lower.contains("frmlogin")
        || forms
            .iter()
            .any(|form| form.has_password_field() || form.is_login_form())
}

fn is_user_confirm_location(location: &str) -> bool {
    location
        .to_ascii_lowercase()
        .replace("%2d", "-")
        .contains(CONTINUATION_MARKER)
}

fn has_continue_field(form: &Form) -> bool {
    form.inputs.iter().any(|input| {
        input.name.as_deref().is_some_and(|name| {
            let name = name.to_ascii_lowercase();
            name.contains("continue") || name.contains("confirm")
        })
    })
}

fn looks_like_continuation_form(form: &Form) -> bool {
    if form.has_password_field() || form.has_token_field() {
        return false;
    }
    form.inputs
        .iter()
        .any(|input| input.type_is("submit") || input.type_is("button"))
        || has_continue_field(form)
}

fn select_continuation_form<'a>(forms: &'a [Form], page: &Url) -> Option<&'a Form> {
    if forms.len() == 1 {
        return forms.first();
    }

    let mut best: Option<(&Form, i32)> = None;
    for form in forms {
        if form.has_password_field() || form.has_token_field() {
            continue;
        }

        let mut score = 0;
        if let Ok(action) = form.resolved_action(page) {
            if action.host.eq_ignore_ascii_case(&page.host) && action.port == page.port {
                score += 4;
            }
        }
        if form
            .inputs
            .iter()
            .any(|input| input.type_is("submit") || input.type_is("button"))
        {
            score += 2;
        }
        if has_continue_field(form) {
            score += 2;
        }
        if score == 0 {
            continue;
        }

        if best.is_none_or(|(_, best_score)| score > best_score) {
            best = Some((form, score));
        }
    }
    best.map(|(form, _)| form)
}

/// Whether this form is the gateway's session-confirmation form.
fn is_confirmation_form(form: &Form) -> bool {
    if form.name_or_id().is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("confirmation") || value.contains("confirmform")
    }) {
        return true;
    }
    form.has_input("FormDataStr") && form.has_input("btnContinue")
}

/// Hidden fields that survive into the credential body.
fn carried_hidden_fields(form: &Form, excluded: &[&str]) -> Vec<(String, String)> {
    form.inputs
        .iter()
        .filter(|input| !input.disabled && input.is_hidden())
        .filter_map(|input| {
            let name = input.name.as_ref()?;
            let lower = name.to_ascii_lowercase();
            if lower.contains("password")
                || lower.contains("token")
                || lower.contains("secret")
                || lower.contains("credential")
                || excluded
                    .iter()
                    .any(|excluded| name.eq_ignore_ascii_case(excluded))
            {
                return None;
            }
            Some((name.clone(), input.value.clone().unwrap_or_default()))
        })
        .collect()
}

fn carried_fields(form: &Form, excluded: &[&str]) -> Vec<(String, String)> {
    form.inputs
        .iter()
        .filter(|input| !input.disabled)
        .filter(|input| input.is_hidden() || input.type_is("submit") || input.type_is("button"))
        .filter_map(|input| {
            let name = input.name.as_ref()?;
            let lower = name.to_ascii_lowercase();
            if lower.contains("password")
                || lower.contains("token")
                || lower.contains("secret")
                || lower.contains("credential")
                || excluded
                    .iter()
                    .any(|excluded| name.eq_ignore_ascii_case(excluded))
            {
                return None;
            }
            Some((name.clone(), input.value.clone().unwrap_or_default()))
        })
        .collect()
}

fn form_urlencode(fields: &[(String, String)]) -> String {
    fields
        .iter()
        .map(|(name, value)| format!("{}={}", encode_component(name), encode_component(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevan_proto::{ScriptedTransport, TlsObservation};
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    const LOGIN_PAGE: &str = include_str!("../tests/fixtures/login-page.html");
    const TOKEN_PAGE: &str = include_str!("../tests/fixtures/token-page.html");
    const REJECTED_PAGE: &str = include_str!("../tests/fixtures/rejected-page.html");
    const SUCCESS_PAGE: &str = include_str!("../tests/fixtures/success-page.html");

    fn base() -> Url {
        Url::parse("https://vpn.example.net/example_realm/").expect("url")
    }

    fn login_form() -> Form {
        parse_forms(LOGIN_PAGE)
            .into_iter()
            .next()
            .expect("login form")
    }

    fn response(status: u16, headers: Vec<(String, String)>, body: &str) -> HttpResponse {
        HttpResponse {
            status_code: status,
            reason: String::new(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    fn observation() -> TlsObservation {
        TlsObservation {
            protocol: "TLSv1_3".into(),
            chain: Vec::new(),
        }
    }

    fn context() -> LoginContext {
        LoginContext::new("0123456789abcdef", 480, 1_760_000_000)
    }

    #[test]
    fn fresh_nonces_are_sixteen_lowercase_hex_characters() {
        let first = random_token();
        let second = random_token();
        assert_eq!(first.len(), 16);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_ne!(first, second);
    }

    #[test]
    fn builds_the_credential_body_in_order() {
        let request = LoginRequest::from_form_with_context(
            &login_form(),
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
            context(),
        )
        .expect("request");
        let body = request.body();

        assert_eq!(
            request.action().to_string(),
            "https://vpn.example.net/example_realm/login.cgi"
        );
        assert_eq!(
            body.as_str(),
            concat!(
                "username=example_user",
                "&password=hunter2",
                "&realm=example_realm",
                "&xsauth=0123456789abcdef",
                "&tz_offset=480",
                "&clienttime=1760000000",
                "&url=",
                "&activex_enabled=0",
                "&java_enabled=0",
                "&clientSrc=203.0.113.10",
            )
        );
        assert!(!body.contains("password%232"));
    }

    #[test]
    fn explicit_fields_override_carried_hidden_duplicates() {
        let html = r#"
            <form id="frmLogin" action="login.cgi" method="post">
              <input type="hidden" name="realm" value="other-realm">
              <input type="hidden" name="tz_offset" value="999">
              <input type="hidden" name="xsauth" value="stale-token">
              <input type="hidden" name="clientMAC" value="00:11:22:33:44:55">
              <input type="text" name="username">
              <input type="password" name="password">
            </form>
        "#;
        let form = parse_forms(html).into_iter().next().expect("form");
        let request = LoginRequest::from_form_with_context(
            &form,
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
            context(),
        )
        .expect("request");
        let body = request.body();

        assert_eq!(body.matches("realm=").count(), 1);
        assert_eq!(body.matches("tz_offset=").count(), 1);
        assert_eq!(body.matches("xsauth=").count(), 1);
        assert!(body.contains("realm=example_realm"));
        assert!(body.contains("tz_offset=480"));
        assert!(body.contains("xsauth=0123456789abcdef"));
        assert!(body.contains("clientMAC=00%3A11%3A22%3A33%3A44%3A55"));
        assert!(!body.contains("other-realm"));
        assert!(!body.contains("stale-token"));
    }

    #[test]
    fn a_resuming_attempt_carries_btn_continue() {
        let request = LoginRequest::new_with_context(
            Url::parse("https://example.net/login.cgi").expect("url"),
            "example_realm",
            "example_user",
            "hunter2",
            context().resuming_session(),
        );
        let body = request.body();
        assert!(body.contains("btnContinue=Continue+the+session"));
    }

    #[test]
    fn field_names_are_recorded_without_values() {
        let request = LoginRequest::from_form_with_context(
            &login_form(),
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
            context(),
        )
        .expect("request");
        let names = request.field_names();
        assert_eq!(
            names,
            vec![
                "username",
                "password",
                "realm",
                "xsauth",
                "tz_offset",
                "clienttime",
                "url",
                "activex_enabled",
                "java_enabled",
                "clientSrc",
            ]
        );
        assert!(!names.iter().any(|name| name.contains("0123456789abcdef")));
    }

    #[test]
    fn percent_encodes_field_names_and_values() {
        let request = LoginRequest::new_with_context(
            Url::parse("https://example.net/login.cgi").expect("url"),
            "example_realm",
            "a b&c",
            "p@ss#1",
            context(),
        );
        let body = request.body();
        assert!(body.contains("username=a+b%26c"));
        assert!(body.contains("password=p%40ss%231"));
    }

    #[test]
    fn submit_performs_exactly_one_post_and_detects_the_token_page() {
        let transport = ScriptedTransport::new([response(200, Vec::new(), TOKEN_PAGE)])
            .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let request = LoginRequest::from_form(
            &login_form(),
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
        )
        .expect("request");

        let outcome = request.submit(&mut client).expect("submit");
        match outcome {
            LoginOutcome::TokenRequired { challenge, .. } => {
                assert_eq!(challenge.token_field, "password#2");
                assert_eq!(
                    challenge.action.to_string(),
                    "https://vpn.example.net/example_realm/login.cgi"
                );
            }
            other => panic!("expected TokenRequired, got {other:?}"),
        }
        assert_eq!(client.transport().requests().len(), 1);
    }

    #[test]
    fn classifies_rejection_from_the_body() {
        let outcome = LoginOutcome::classify(&response(200, Vec::new(), REJECTED_PAGE), &base());
        assert!(matches!(outcome, LoginOutcome::Rejected { .. }));
    }

    #[test]
    fn classifies_rejection_from_the_status() {
        let outcome = LoginOutcome::classify(&response(403, Vec::new(), ""), &base());
        assert!(matches!(
            outcome,
            LoginOutcome::Rejected {
                status_code: 403,
                ..
            }
        ));
    }

    #[test]
    fn classifies_success_from_the_body() {
        let outcome = LoginOutcome::classify(&response(200, Vec::new(), SUCCESS_PAGE), &base());
        assert!(matches!(outcome, LoginOutcome::Success { .. }));
    }

    #[test]
    fn a_302_to_welcome_is_rejected_as_a_bounce() {
        let outcome = LoginOutcome::classify(
            &response(
                302,
                vec![(
                    "Location".into(),
                    "/dana-na/auth/url_default/welcome.cgi".into(),
                )],
                "",
            ),
            &base(),
        );
        match outcome {
            LoginOutcome::Rejected { reason, .. } => {
                assert!(reason.contains("sign-in page"), "{reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn a_302_to_login_is_rejected_as_a_bounce() {
        let outcome = LoginOutcome::classify(
            &response(
                302,
                vec![(
                    "Location".into(),
                    "/dana-na/auth/url_default/login.cgi".into(),
                )],
                "",
            ),
            &base(),
        );
        assert!(matches!(
            outcome,
            LoginOutcome::Rejected { ref reason, .. } if reason.contains("sign-in page")
        ));
    }

    #[test]
    fn a_302_to_dana_na_with_a_session_cookie_is_success() {
        let outcome = LoginOutcome::classify(
            &response(
                302,
                vec![
                    ("Location".into(), "/dana-na/".into()),
                    (
                        "Set-Cookie".into(),
                        "DSID=secret-session; Path=/; Secure; HttpOnly".into(),
                    ),
                ],
                "",
            ),
            &base(),
        );
        match outcome {
            LoginOutcome::Success { location, .. } => {
                assert_eq!(location.as_deref(), Some("/dana-na/"));
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[test]
    fn a_session_cookie_on_a_welcome_redirect_also_counts_as_success() {
        let outcome = LoginOutcome::classify(
            &response(
                302,
                vec![
                    (
                        "Location".into(),
                        "/dana-na/auth/url_default/welcome.cgi".into(),
                    ),
                    ("Set-Cookie".into(), "DSSIGNIN=abc; Path=/".into()),
                ],
                "",
            ),
            &base(),
        );
        assert!(matches!(outcome, LoginOutcome::Success { .. }));
    }

    #[test]
    fn a_200_sign_in_page_without_a_session_cookie_is_rejected() {
        let outcome = LoginOutcome::classify(&response(200, Vec::new(), LOGIN_PAGE), &base());
        match outcome {
            LoginOutcome::Rejected { reason, .. } => {
                assert!(reason.contains("sign-in page"), "{reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn an_unrecognised_page_without_a_session_cookie_is_rejected() {
        let outcome = LoginOutcome::classify(
            &response(200, Vec::new(), "<html><body>maintenance</body></html>"),
            &base(),
        );
        match outcome {
            LoginOutcome::Rejected { reason, .. } => {
                assert!(reason.contains("no session cookie"), "{reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn token_continuation_is_one_post_and_keeps_carried_fields() {
        let challenge = TokenChallenge {
            action: Url::parse("https://vpn.example.net/example_realm/login.cgi").expect("url"),
            hidden: vec![
                ("realm".into(), "example_realm".into()),
                ("clientSrc".into(), "203.0.113.10".into()),
            ],
            token_field: "password#2".into(),
        };
        let request = TokenRequest::from_challenge(&challenge, "123456");
        let body = request.body();
        assert!(body.contains("realm=example_realm"));
        assert!(body.contains("clientSrc=203.0.113.10"));
        assert!(body.contains("password%232=123456"));

        let transport = ScriptedTransport::new([response(200, Vec::new(), SUCCESS_PAGE)])
            .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let outcome = request.submit(&mut client).expect("submit");
        assert!(matches!(outcome, LoginOutcome::Success { .. }));
        assert_eq!(client.transport().requests().len(), 1);
    }

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buffer").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
        type Writer = Buffer;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    const CONFIRM_PAGE: &str = r#"
        <html><body>
        <form id="frmConfirm" action="welcome.cgi" method="post">
          <input type="hidden" name="id" value="state-value">
          <input type="hidden" name="confirm" value="1">
          <input type="submit" name="btnContinue" value="Continue">
        </form>
        </body></html>
    "#;

    const DASHBOARD_PAGE: &str =
        r#"<html><body><div id="frmDashboard">Welcome</div></body></html>"#;

    const DSID_CONFIRM_PAGE: &str = r#"
        <html><body>
        <form id="DSIDConfirmForm" name="frmConfirmation" method="post" action="login.cgi">
          <input id="btnContinue" type="submit" name="btnContinue" value="Continue the session">
          <input id="btnCancel" type="submit" name="btnCancel" value="Cancel">
          <input id="DSIDFormDataStr" type="hidden" name="FormDataStr" value="opaque-state">
        </form>
        </body></html>
    "#;

    fn user_confirm() -> Vec<(String, String)> {
        vec![(
            "Location".into(),
            "/dana-na/auth/url_default/welcome.cgi?p=user%2Dconfirm".into(),
        )]
    }

    #[test]
    fn classifies_the_user_confirm_redirect_before_success() {
        let outcome = LoginOutcome::classify(
            &response(302, user_confirm(), ""),
            &Url::parse("https://example.net/dana-na/auth/login.cgi").expect("url"),
        );
        match outcome {
            LoginOutcome::ContinuationRequired { challenge, .. } => {
                assert!(challenge.location.is_some());
            }
            other => panic!("expected ContinuationRequired, got {other:?}"),
        }
    }

    #[test]
    fn continuation_gets_the_page_and_posts_the_form_once() {
        let transport = ScriptedTransport::new([
            response(302, user_confirm(), ""),
            response(200, Vec::new(), CONFIRM_PAGE),
            response(200, Vec::new(), DASHBOARD_PAGE),
        ])
        .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let request = LoginRequest::from_form(
            &login_form(),
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
        )
        .expect("request");

        let submission = request
            .submit_with_response(&mut client)
            .expect("credential post");
        let challenge = match &submission.outcome {
            LoginOutcome::ContinuationRequired { challenge, .. } => challenge.clone(),
            other => panic!("expected ContinuationRequired, got {other:?}"),
        };

        let exchange =
            complete_continuation(&mut client, &challenge, request.action()).expect("continuation");
        assert!(matches!(
            exchange.submission.outcome,
            LoginOutcome::Success { .. }
        ));
        assert_eq!(exchange.observation.hops.len(), 2);
        assert!(exchange
            .observation
            .page_html
            .as_deref()
            .expect("captured html")
            .contains("frmConfirm"));

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].method, "GET");
        assert_eq!(requests[2].method, "POST");
        let body = String::from_utf8(requests[2].body.clone()).expect("body");
        assert!(body.contains("id=state-value"));
        assert!(body.contains("confirm=1"));
        assert!(body.contains("btnContinue=Continue"));
        assert!(!body.contains("password"));
    }

    #[test]
    fn a_confirmation_page_served_by_the_credential_post_is_answered_directly() {
        let transport = ScriptedTransport::new([
            response(200, Vec::new(), DSID_CONFIRM_PAGE),
            response(200, Vec::new(), DASHBOARD_PAGE),
        ])
        .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let request = LoginRequest::from_form_with_context(
            &login_form(),
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
            context(),
        )
        .expect("request");

        let submission = request
            .submit_with_response(&mut client)
            .expect("credential post");
        let challenge = match &submission.outcome {
            LoginOutcome::ContinuationRequired { challenge, .. } => challenge.clone(),
            other => panic!("expected ContinuationRequired, got {other:?}"),
        };
        assert!(challenge.page_html.is_some());

        let exchange =
            complete_continuation(&mut client, &challenge, request.action()).expect("continuation");
        assert!(matches!(
            exchange.submission.outcome,
            LoginOutcome::Success { .. }
        ));

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 2, "credential POST plus one direct answer");
        assert_eq!(requests[1].method, "POST");
        let body = String::from_utf8(requests[1].body.clone()).expect("body");
        assert!(body.contains("FormDataStr=opaque-state"));
        assert!(body.contains("btnContinue=Continue+the+session"));
        assert!(!body.contains("btnCancel"));
    }

    #[test]
    fn a_confirmation_answer_that_bounces_to_welcome_is_rejected() {
        let transport = ScriptedTransport::new([
            response(200, Vec::new(), DSID_CONFIRM_PAGE),
            response(
                302,
                vec![(
                    "Location".into(),
                    "/dana-na/auth/url_default/welcome.cgi".into(),
                )],
                "",
            ),
        ])
        .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let request = LoginRequest::from_form_with_context(
            &login_form(),
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
            context(),
        )
        .expect("request");

        let submission = request
            .submit_with_response(&mut client)
            .expect("credential post");
        let challenge = match &submission.outcome {
            LoginOutcome::ContinuationRequired { challenge, .. } => challenge.clone(),
            other => panic!("expected ContinuationRequired, got {other:?}"),
        };
        let exchange =
            complete_continuation(&mut client, &challenge, request.action()).expect("continuation");
        match exchange.submission.outcome {
            LoginOutcome::Rejected { reason, .. } => {
                assert!(reason.contains("sign-in page"), "{reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn continuation_page_without_a_form_is_a_typed_error() {
        let transport = ScriptedTransport::new([
            response(302, user_confirm(), ""),
            response(200, Vec::new(), "<html><body>no form here</body></html>"),
        ]);
        let mut client = HttpClient::new(transport);
        let request = LoginRequest::from_form(
            &login_form(),
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
        )
        .expect("request");
        let submission = request
            .submit_with_response(&mut client)
            .expect("credential post");
        let challenge = match &submission.outcome {
            LoginOutcome::ContinuationRequired { challenge, .. } => challenge.clone(),
            other => panic!("expected ContinuationRequired, got {other:?}"),
        };

        let error = complete_continuation(&mut client, &challenge, request.action())
            .expect_err("must fail");
        assert!(matches!(error, ContinuationError::NoForm));
        assert_eq!(client.transport().requests().len(), 2);
    }

    #[test]
    fn a_second_user_confirm_page_is_rejected_without_another_post() {
        let transport = ScriptedTransport::new([
            response(302, user_confirm(), ""),
            response(200, Vec::new(), CONFIRM_PAGE),
            response(302, user_confirm(), ""),
        ]);
        let mut client = HttpClient::new(transport);
        let request = LoginRequest::from_form(
            &login_form(),
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
        )
        .expect("request");
        let submission = request
            .submit_with_response(&mut client)
            .expect("credential post");
        let challenge = match &submission.outcome {
            LoginOutcome::ContinuationRequired { challenge, .. } => challenge.clone(),
            other => panic!("expected ContinuationRequired, got {other:?}"),
        };

        let error = complete_continuation(&mut client, &challenge, request.action())
            .expect_err("must fail");
        assert!(matches!(error, ContinuationError::LoopDetected));
        let requests = client.transport().requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST")
                .count(),
            2,
            "one credential POST plus exactly one continuation POST"
        );
    }

    #[test]
    fn login_body_never_appears_in_a_tracing_capture() {
        let transport = ScriptedTransport::new([response(200, Vec::new(), TOKEN_PAGE)])
            .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let request = LoginRequest::from_form(
            &login_form(),
            &base(),
            "example_realm",
            "example_user",
            "hunter2",
        )
        .expect("request");

        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(buffer.clone())
            .finish();
        let outcome = tracing::subscriber::with_default(subscriber, || {
            // A callsite used only here proves the capture itself works even if
            // another test caused the submit callsite to cache a disabled
            // interest before this subscriber existed.
            tracing::debug!("tracing capture armed");
            request.submit(&mut client)
        })
        .expect("submit");
        assert!(matches!(outcome, LoginOutcome::TokenRequired { .. }));

        let captured = String::from_utf8(buffer.0.lock().expect("buffer").clone())
            .expect("captured logs are UTF-8");
        assert!(
            captured.contains("tracing capture armed"),
            "debug logging must be captured: {captured}"
        );
        assert!(!captured.contains("hunter2"));
        assert!(!captured.contains("example_user"));
        assert!(!captured.contains("password=hunter2"));

        let sent = String::from_utf8(client.transport().requests()[0].body.clone())
            .expect("request body is UTF-8");
        assert!(
            sent.contains("password=hunter2"),
            "the body must actually contain the password"
        );
    }
}
