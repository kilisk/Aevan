//! Shared authentication orchestration.
//!
//! This is the single credential path used by `aevan login`, `aevan config
//! --live`, foreground `aevan connect` and the daemon. It performs exactly one
//! credential POST; only a recognised token challenge may add its single
//! continuation POST. There is no retry loop, no profile switch and no fallback
//! host.
//!
//! Credentials are supplied by the caller. The CLI reads them from the TTY and
//! the daemon receives them over its local control socket; this module never
//! reads argv, the environment or the terminal itself.

use std::time::Duration;

use zeroize::Zeroizing;

use aevan_core::{AevanError, AevanResult, Profile};
use aevan_nc::{
    complete_continuation, AuthObservation, AuthProbe, ContinuationError, ContinuationObservation,
    LoginOutcome, LoginRequest, LoginSubmission, TokenRequest, DEFAULT_MAX_REDIRECTS,
};
use aevan_proto::{HttpClient, HttpResponse, ProtoError, TlsTransport, Url};

/// Timeout for one HTTP operation inside the login exchange.
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);

/// Credentials for one authentication attempt.
///
/// The type implements no `Debug` or `Display`, and the secret fields zeroize
/// when dropped.
pub struct AuthCredentials {
    /// Username for the login form.
    pub username: String,
    /// Password. Zeroized on drop.
    pub password: Zeroizing<String>,
    /// Optional secondary token. Zeroized on drop.
    pub token: Option<Zeroizing<String>>,
}

impl AuthCredentials {
    /// Build a credential set.
    pub fn new(
        username: impl Into<String>,
        password: Zeroizing<String>,
        token: Option<Zeroizing<String>>,
    ) -> Self {
        Self {
            username: username.into(),
            password,
            token,
        }
    }
}

/// An authenticated HTTP session plus the observations needed for a dump.
pub struct LoginSession {
    /// HTTP client whose cookie jar now carries the session.
    pub client: HttpClient<TlsTransport>,
    /// Credential-free probe facts, including the redirect chain.
    pub probe: AuthObservation,
    /// Successful login outcome.
    pub outcome: LoginOutcome,
    /// Whether the secondary token was submitted.
    pub token_submitted: bool,
    /// The user-confirm exchange, when the gateway required one.
    pub continuation: Option<ContinuationObservation>,
    /// Raw response that produced the successful outcome.
    pub final_response: HttpResponse,
    /// Credential POST field names in wire order, never values.
    pub login_field_names: Vec<String>,
}

fn parse_url(raw: &str) -> AevanResult<Url> {
    Url::parse(raw).map_err(|error| AevanError::Config(error.to_string()))
}

fn network_error(error: ProtoError) -> AevanError {
    match error {
        ProtoError::InvalidUrl(message) => AevanError::Config(format!("invalid URL: {message}")),
        other => AevanError::Network(other.to_string()),
    }
}

fn continuation_error(error: ContinuationError) -> AevanError {
    match error {
        ContinuationError::Transport(error) => network_error(error),
        ContinuationError::NoForm => {
            AevanError::Unsupported("the user-confirm page served no continuation form".into())
        }
        ContinuationError::LoopDetected => AevanError::Unsupported(
            "gateway asked for a second user-confirm page; refusing to continue".into(),
        ),
    }
}

/// Authenticate an already selected profile with exactly one attempt.
///
/// `prompt_token` is called only when the gateway asks for a secondary token and
/// none was supplied up front. The CLI passes a TTY closure; the daemon passes
/// `None`, which turns an unexpected challenge into exit code 2 without another
/// credential POST.
pub fn authenticate<F>(
    profile: &Profile,
    credentials: AuthCredentials,
    mut prompt_token: F,
) -> AevanResult<LoginSession>
where
    F: FnMut() -> AevanResult<Option<Zeroizing<String>>>,
{
    let url = parse_url(&profile.url)?;

    if credentials.username.trim().is_empty() {
        return Err(AevanError::Config("username must not be empty".into()));
    }
    if credentials.password.is_empty() {
        return Err(AevanError::Config("password must not be empty".into()));
    }

    let username = credentials.username;
    let password = credentials.password;
    let mut token = credentials.token;

    let transport = TlsTransport::new(NETWORK_TIMEOUT);
    let mut client = HttpClient::with_max_redirects(transport, DEFAULT_MAX_REDIRECTS);

    let observation = AuthProbe::new()
        .run(&mut client, &url)
        .map_err(network_error)?;

    let Some(form) = observation.login_form.as_ref() else {
        return Err(AevanError::Unsupported(format!(
            "no login form was found (final HTTP {} at {})",
            observation.final_status, observation.final_url
        )));
    };
    let base = parse_url(&observation.final_url)?;
    let request =
        LoginRequest::from_form(form, &base, &profile.realm, &username, password.as_str())
            .map_err(network_error)?;
    let login_field_names = request.field_names();

    let mut submission = request
        .submit_with_response(&mut client)
        .map_err(network_error)?;
    let mut last_action = request.action().clone();
    let mut token_submitted = false;

    let challenge = match &submission.outcome {
        LoginOutcome::TokenRequired { challenge, .. } => Some(challenge.clone()),
        _ => None,
    };
    if let Some(challenge) = challenge {
        let value = match token.take() {
            Some(value) => Some(value),
            None => prompt_token()?,
        };
        let Some(value) = value else {
            return Err(AevanError::Interaction(
                "secondary token required (use --token-stdin)".into(),
            ));
        };

        // The single continuation for the challenge. This is not a retry of the
        // password POST.
        let token_request = TokenRequest::from_challenge(&challenge, value.as_str());
        last_action = token_request.action().clone();
        submission = token_request
            .submit_with_response(&mut client)
            .map_err(network_error)?;
        token_submitted = true;
    }

    // `p=user-confirm` means the gateway already has a session and needs the
    // confirmation form answered. It is part of this exchange, not a retry:
    // exactly one GET chain and exactly one continuation POST.
    let continuation_challenge = match &submission.outcome {
        LoginOutcome::ContinuationRequired { challenge, .. } => Some(challenge.clone()),
        _ => None,
    };
    let mut continuation = None;
    if let Some(challenge) = continuation_challenge {
        match complete_continuation(&mut client, &challenge, &last_action) {
            Ok(exchange) => {
                continuation = Some(exchange.observation);
                submission = exchange.submission;
            }
            Err(error) => return Err(continuation_error(error)),
        }
    }

    let LoginSubmission {
        outcome,
        response,
        request_field_names: _,
    } = submission;
    match &outcome {
        LoginOutcome::Success { .. } => Ok(LoginSession {
            client,
            probe: observation,
            outcome,
            token_submitted,
            continuation,
            final_response: response,
            login_field_names,
        }),
        LoginOutcome::TokenRequired { .. } => Err(AevanError::Unsupported(
            "gateway requested a second token; refusing to retry".into(),
        )),
        LoginOutcome::ContinuationRequired { .. } => Err(AevanError::Unsupported(
            "gateway asked for a second user-confirm page; refusing to continue".into(),
        )),
        LoginOutcome::Rejected {
            status_code,
            reason,
        } => Err(AevanError::AuthRejected(format!(
            "{reason} (HTTP {status_code})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevan_nc::{complete_continuation, ContinuationError, LoginContext};
    use aevan_proto::{HttpClient, HttpResponse, ScriptedTransport, TlsObservation};

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

    fn observation() -> TlsObservation {
        TlsObservation {
            protocol: "TLSv1_3".into(),
            chain: Vec::new(),
        }
    }

    const CONFIRM_PAGE: &str = r#"
        <form id="frmConfirm" action="welcome.cgi" method="post">
          <input type="hidden" name="id" value="state-value">
          <input type="submit" name="btnContinue" value="Continue">
        </form>
    "#;

    fn user_confirm() -> Vec<(&'static str, &'static str)> {
        vec![(
            "Location",
            "/dana-na/auth/url_default/welcome.cgi?p=user%2Dconfirm",
        )]
    }

    #[test]
    fn a_second_user_confirm_maps_to_exit_7_and_one_continuation_post() {
        let transport = ScriptedTransport::new([
            response(302, user_confirm(), ""),
            response(200, Vec::new(), CONFIRM_PAGE),
            response(302, user_confirm(), ""),
        ])
        .with_observation(observation());
        let mut client = HttpClient::new(transport);
        let request = LoginRequest::new_with_context(
            Url::parse("https://example.net/dana-na/auth/login.cgi").expect("url"),
            "realm",
            "example_user",
            "hunter2",
            LoginContext::new("0123456789abcdef", 480, 1_760_000_000),
        );

        let submission = request
            .submit_with_response(&mut client)
            .expect("credential post");
        let challenge = match &submission.outcome {
            LoginOutcome::ContinuationRequired { challenge, .. } => challenge.clone(),
            other => panic!("expected ContinuationRequired, got {other:?}"),
        };

        let error = complete_continuation(&mut client, &challenge, request.action())
            .expect_err("must stop at the second user-confirm page");
        let mapped = continuation_error(error);
        assert!(matches!(mapped, AevanError::Unsupported(_)));
        assert_eq!(mapped.exit_code(), 7);

        let posts = client
            .transport()
            .requests()
            .iter()
            .filter(|request| request.method == "POST")
            .count();
        assert_eq!(posts, 2, "credential POST plus one continuation POST");
    }

    #[test]
    fn a_missing_continuation_form_maps_to_a_typed_exit_7() {
        let mapped = continuation_error(ContinuationError::NoForm);
        assert!(matches!(mapped, AevanError::Unsupported(_)));
        assert_eq!(mapped.exit_code(), 7);
    }

    #[test]
    fn credentials_cannot_be_debugged() {
        fn assert_no_debug<T>() {}
        // Compile-time guard: AuthCredentials deliberately has no Debug.
        assert_no_debug::<AuthCredentials>();
    }
}
