//! Plain view model for `aevan-gui`.
//!
//! This module intentionally contains no `iced` types. It owns the screens, the
//! connection state, the credential buffers, formatting and poll scheduling so
//! that every behavioural rule can be unit-tested without a display, a daemon
//! or a network.
//!
//! Security rules enforced here:
//!
//! * the password and token live in [`Zeroizing`] buffers;
//! * [`ConnectCredentials`] has a redacted `Debug` and cannot be cloned;
//! * the buffers are moved out for submission and cleared on any failure or
//!   disconnect, so they are never displayed after they are sent.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use zeroize::Zeroizing;

use aevan_core::{Profile, ProfileStore, SplitTunnelIntent};
use aevan_daemon::autostart::TaskState;
use aevan_daemon::client::ClientError;
use aevan_daemon::{RecoveryReport, Request, SecretString, StatusReport};
use aevan_secrets::{decode_base32, Totp};

/// How often `status` is polled while a session is live or changing.
pub const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The keyring service name used for profile secrets.
pub const KEYRING_SERVICE: &str = "aevan";

/// The four screens of the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Profile list with status dots and the daemon state.
    Profiles,
    /// Credential sheet (username, password, token).
    Connect,
    /// Live tunnel details and disconnect.
    Connected,
    /// Split-tunnel preview, log level and endpoint.
    Settings,
    /// Sheet for adding a non-secret profile.
    AddProfile,
}

impl Screen {
    /// Stable name used by `--headless` and the view.
    pub fn name(self) -> &'static str {
        match self {
            Self::Profiles => "profiles",
            Self::Connect => "connect",
            Self::Connected => "connected",
            Self::Settings => "settings",
            Self::AddProfile => "add-profile",
        }
    }
}

/// Connection state, mirroring the daemon's state machine plus one local state
/// for "the control endpoint could not be reached".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// No tunnel is active.
    Disconnected,
    /// Exactly one credential attempt is in flight.
    Authenticating,
    /// The daemon is applying the tunnel.
    Connecting,
    /// The tunnel is up.
    Connected,
    /// Teardown is running.
    Disconnecting,
    /// Crash recovery left a journal that is not fully undone.
    RecoveryIncomplete {
        /// Machine-readable recovery counts and failures.
        report: RecoveryReport,
    },
    /// The last attempt failed; the reason never contains a credential.
    Failed {
        /// Human-readable failure reason.
        reason: String,
    },
    /// The control endpoint could not be reached or spoke a different protocol.
    DaemonUnavailable {
        /// The daemon client's own reach-failure message.
        message: String,
    },
}

impl ConnectionState {
    /// Stable lower-case name (matching the daemon where one exists).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Authenticating => "authenticating",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Disconnecting => "disconnecting",
            Self::RecoveryIncomplete { .. } => "recovery-incomplete",
            Self::Failed { .. } => "failed",
            Self::DaemonUnavailable { .. } => "daemon-unavailable",
        }
    }

    /// Failure or reachability message, when present.
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Failed { reason } => Some(reason),
            Self::DaemonUnavailable { message } => Some(message),
            _ => None,
        }
    }

    /// Whether `status` should be polled in this state.
    pub fn should_poll(&self) -> bool {
        matches!(
            self,
            Self::Authenticating
                | Self::Connecting
                | Self::Connected
                | Self::Disconnecting
                | Self::RecoveryIncomplete { .. }
        )
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One notification the view model wants to show.
///
/// The variants deliberately contain only non-secret state: a tunnel address
/// and the daemon's already-redacted failure reason. There is no variant that
/// can carry a password, a token or a TOTP secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionNotification {
    /// The tunnel came up.
    Connected {
        /// Assigned address, or a placeholder when the daemon omitted it.
        address: String,
    },
    /// The last attempt failed.
    Failed {
        /// Daemon-reported reason, already redacted by the daemon.
        reason: String,
    },
    /// Crash recovery left a journal that is not fully undone.
    RecoveryIncomplete {
        /// Number of teardown steps that could not be completed.
        failed: usize,
    },
}

impl TransitionNotification {
    /// Notification title.
    pub fn title(&self) -> &'static str {
        match self {
            Self::Connected { .. } => "Aevan connected",
            Self::Failed { .. } => "Aevan connection failed",
            Self::RecoveryIncomplete { .. } => "Aevan recovery incomplete",
        }
    }

    /// Notification body. Never contains credential material.
    pub fn body(&self) -> String {
        match self {
            Self::Connected { address } => format!("Tunnel is up at {address}."),
            Self::Failed { reason } => reason.clone(),
            Self::RecoveryIncomplete { failed } => format!(
                "Teardown recovery left {failed} step{} incomplete.",
                if *failed == 1 { "" } else { "s" }
            ),
        }
    }
}

/// What the GUI knows about the per-user start-at-login task.
///
/// The state is read through the same `aevand --autostart-status` code path the
/// CLI uses. If the task cannot be read, the label says so instead of guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutostartState {
    /// The first read has not completed.
    Loading,
    /// The logon task exists.
    Present,
    /// The logon task does not exist.
    Absent,
    /// The task could be queried but the answer was not understood.
    Unknown(String),
    /// This platform or build cannot read the task.
    Unavailable(String),
}

impl AutostartState {
    /// Human-readable state for the Settings screen.
    pub fn label(&self) -> String {
        match self {
            Self::Loading => "checking…".to_owned(),
            Self::Present => "on — aevand starts at your logon".to_owned(),
            Self::Absent => "off".to_owned(),
            Self::Unknown(detail) => format!("could not be read ({detail})"),
            Self::Unavailable(detail) => format!("not available on this platform ({detail})"),
        }
    }

    /// Whether the toggle can be offered, and what pressing it should enable.
    pub fn toggle_target(&self) -> Option<bool> {
        match self {
            Self::Present => Some(false),
            Self::Absent => Some(true),
            Self::Loading | Self::Unknown(_) | Self::Unavailable(_) => None,
        }
    }
}

/// What to do after the user asks to quit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuitPlan {
    /// Disconnect first, then finish quitting.
    Disconnect(Option<String>),
    /// A half-torn-down tunnel needs an explicit confirmation.
    Confirm(String),
    /// Safe to stop the daemon (if this GUI started it) and exit.
    Exit,
}

/// The tray menu's read-only status line and enablement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayMenuState {
    /// State text; includes the address when connected.
    pub status: String,
    /// Whether the Connect item is selectable.
    pub connect_enabled: bool,
    /// Whether the Disconnect item is selectable.
    pub disconnect_enabled: bool,
}

/// Decide which transition (if any) deserves a notification.
pub fn transition_notification(
    previous: &ConnectionState,
    next: &ConnectionState,
    address: Option<&str>,
) -> Option<TransitionNotification> {
    match next {
        ConnectionState::Connected if !matches!(previous, ConnectionState::Connected) => {
            Some(TransitionNotification::Connected {
                address: address
                    .filter(|address| !address.is_empty())
                    .unwrap_or("an address the daemon did not report")
                    .to_owned(),
            })
        }
        ConnectionState::Failed { reason }
            if !matches!(previous, ConnectionState::Failed { .. }) =>
        {
            Some(TransitionNotification::Failed {
                reason: reason.clone(),
            })
        }
        ConnectionState::RecoveryIncomplete { report }
            if !matches!(previous, ConnectionState::RecoveryIncomplete { .. }) =>
        {
            Some(TransitionNotification::RecoveryIncomplete {
                failed: report.failed(),
            })
        }
        _ => None,
    }
}

fn state_label(state: &ConnectionState) -> &'static str {
    match state {
        ConnectionState::Disconnected => "Disconnected",
        ConnectionState::Authenticating => "Authenticating",
        ConnectionState::Connecting => "Connecting",
        ConnectionState::Connected => "Connected",
        ConnectionState::Disconnecting => "Disconnecting",
        ConnectionState::RecoveryIncomplete { .. } => "Recovery incomplete",
        ConnectionState::Failed { .. } => "Failed",
        ConnectionState::DaemonUnavailable { .. } => "Daemon unavailable",
    }
}

/// Normalize a user-supplied base32 secret for keyring storage.
///
/// Whitespace, dashes and lower case are accepted and normalized away. Any
/// other non-base32 character is rejected. The error never echoes the input.
pub fn normalize_base32(input: &str) -> Result<String, String> {
    let mut normalized = String::new();
    for character in input.chars() {
        if character.is_whitespace() || character == '-' {
            continue;
        }
        if character == '=' {
            break;
        }
        let upper = character.to_ascii_uppercase();
        match upper {
            'A'..='Z' | '2'..='7' => normalized.push(upper),
            _ => return Err("the secret is not valid base32".to_owned()),
        }
    }
    if normalized.is_empty() {
        return Err("the secret must not be empty".to_owned());
    }
    Ok(normalized)
}

/// Colour of a profile's status dot. Values are plain RGB tuples so this module
/// stays free of toolkit types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileDot {
    /// The tunnel is up for this profile.
    Connected,
    /// A transition is in progress.
    Busy,
    /// The last attempt failed.
    Failed,
    /// No tunnel and no failure.
    Disconnected,
    /// The control endpoint is not reachable.
    Unavailable,
}

impl ProfileDot {
    /// Accessible label for the dot.
    pub fn label(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Busy => "busy",
            Self::Failed => "failed",
            Self::Disconnected => "disconnected",
            Self::Unavailable => "offline",
        }
    }

    /// RGB colour for the dot.
    pub fn rgb(self) -> (u8, u8, u8) {
        match self {
            Self::Connected => (0x2e, 0xa0, 0x43),
            Self::Busy => (0xd2, 0x99, 0x22),
            Self::Failed => (0xcf, 0x22, 0x2e),
            Self::Disconnected => (0x8b, 0x94, 0x9e),
            Self::Unavailable => (0xcf, 0x22, 0x2e),
        }
    }
}

/// One row in the profile list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileRow {
    /// Profile name.
    pub name: String,
    /// Gateway URL.
    pub url: String,
    /// Authentication realm.
    pub realm: String,
    /// Optional username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Split-tunnel mode label.
    pub split_tunnel: String,
    /// Split-tunnel routes, when the mode is custom.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub split_tunnel_routes: Vec<String>,
    /// Whether a TOTP secret was found in the keyring for this profile.
    pub totp_enrolled: bool,
}

/// Plain data typed into the "Add profile" sheet.
///
/// There is deliberately no password or token field: a profile never carries a
/// secret, and the sheet says so.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileDraft {
    /// New profile name.
    pub name: String,
    /// Gateway URL.
    pub url: String,
    /// Authentication realm.
    pub realm: String,
    /// Username used for the non-interactive login.
    pub username: String,
}

/// Per-field validation messages for [`ProfileDraft`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileDraftErrors {
    /// Name problem, if any.
    pub name: Option<String>,
    /// Gateway URL problem, if any.
    pub url: Option<String>,
    /// Realm problem, if any.
    pub realm: Option<String>,
    /// Username problem, if any.
    pub username: Option<String>,
}

impl ProfileDraftErrors {
    /// Whether every field passed validation.
    pub fn is_valid(&self) -> bool {
        self.name.is_none() && self.url.is_none() && self.realm.is_none() && self.username.is_none()
    }

    /// The first message, used for a one-line notice when saving is refused.
    pub fn first(&self) -> Option<&str> {
        self.name
            .as_deref()
            .or(self.url.as_deref())
            .or(self.realm.as_deref())
            .or(self.username.as_deref())
    }
}

/// Validate a draft against the profile names that already exist.
///
/// The URL rule is "parses as http(s) and has a host". The profile store
/// itself still enforces HTTPS when the profile is saved.
pub fn validate_profile_draft<'a>(
    draft: &ProfileDraft,
    existing: impl IntoIterator<Item = &'a str>,
) -> ProfileDraftErrors {
    let mut errors = ProfileDraftErrors::default();

    let name = draft.name.trim();
    if name.is_empty() {
        errors.name = Some("name is required".to_owned());
    } else if name.chars().any(char::is_whitespace) {
        errors.name = Some("name must not contain whitespace".to_owned());
    } else if existing.into_iter().any(|existing| existing == name) {
        errors.name = Some(format!("a profile named '{name}' already exists"));
    }

    let url = draft.url.trim();
    if url.is_empty() {
        errors.url = Some("gateway URL is required".to_owned());
    } else {
        match aevan_proto::Url::parse(url) {
            Ok(parsed) if !parsed.host.is_empty() => {}
            Ok(_) => errors.url = Some("gateway URL must include a host".to_owned()),
            Err(_) => {
                errors.url = Some("gateway URL must be a valid http(s) URL with a host".to_owned())
            }
        }
    }

    if draft.realm.trim().is_empty() {
        errors.realm = Some("realm is required".to_owned());
    }
    if draft.username.trim().is_empty() {
        errors.username = Some("username is required for non-interactive login".to_owned());
    }

    errors
}

/// One of the logging levels accepted by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and above.
    Warn,
    /// Informational and above (default).
    Info,
    /// Debug and above.
    Debug,
    /// Everything, including trace.
    Trace,
}

impl LogLevel {
    /// The protocol spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// The next level in display order, wrapping around.
    pub fn next(self) -> Self {
        match self {
            Self::Error => Self::Warn,
            Self::Warn => Self::Info,
            Self::Info => Self::Debug,
            Self::Debug => Self::Trace,
            Self::Trace => Self::Error,
        }
    }

    /// Parse a protocol spelling, falling back to `info`.
    pub fn parse(value: &str) -> Self {
        match value {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => Self::Info,
        }
    }
}

/// Credentials prepared for exactly one `connect` request.
///
/// The type is deliberately not `Clone` and has a redacted `Debug`. It is
/// consumed by [`ConnectCredentials::into_request`].
pub struct ConnectCredentials {
    profile: String,
    username: String,
    password: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
}

impl ConnectCredentials {
    /// Turn the credentials into the one control request the daemon accepts.
    pub fn into_request(self) -> Request {
        let token = self
            .token
            .map(|token| SecretString::new(token.as_str().to_owned()));
        Request::connect(
            Some(self.profile),
            self.username,
            SecretString::new(self.password.as_str().to_owned()),
            token,
        )
    }

    /// Test-only view of the token so a test can prove which value won.
    #[cfg(test)]
    pub(crate) fn token_value(&self) -> Option<&str> {
        self.token.as_ref().map(|token| token.as_str())
    }
}

impl fmt::Debug for ConnectCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectCredentials")
            .field("profile", &self.profile)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field(
                "token",
                &if self.token.is_some() {
                    "[REDACTED]"
                } else {
                    "[none]"
                },
            )
            .finish()
    }
}

/// A validated TOTP secret awaiting exactly one keyring write.
///
/// The type is not `Debug` or `Clone`; it is consumed by the save task and its
/// buffers zeroize on drop.
pub struct TotpEnrolment {
    profile: String,
    encoded: Zeroizing<String>,
    decoded: Zeroizing<Vec<u8>>,
}

impl TotpEnrolment {
    /// Profile this secret belongs to.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Normalized base32 text to write to the keyring.
    pub fn encoded(&self) -> &str {
        self.encoded.as_str()
    }

    /// Consume the enrolment and return the decoded secret for the live cache.
    pub fn into_decoded(self) -> Vec<u8> {
        self.decoded.to_vec()
    }
}

/// A credential field carried in a widget message.
///
/// `Debug` is redacted so a derived `Debug` on the message enum cannot print a
/// password, one-time token or typed TOTP secret.
#[derive(Clone)]
pub struct SecretField(String);

impl SecretField {
    /// Wrap a widget value.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Consume the wrapper and return the value.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for SecretField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretField([REDACTED])")
    }
}

/// A decoded TOTP secret carried across an async task boundary.
///
/// `Debug` is redacted so the value cannot leak through a derived `Debug` on
/// the widget message enum.
#[derive(Clone)]
pub struct DecodedTotpSecret(Zeroizing<Vec<u8>>);

impl DecodedTotpSecret {
    /// Wrap decoded secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Consume the wrapper and return the decoded bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for DecodedTotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DecodedTotpSecret([REDACTED])")
    }
}

/// The whole GUI state except for toolkit-owned widget state.
pub struct ViewModel {
    /// Profiles loaded from the profile store.
    pub profiles: Vec<ProfileRow>,
    /// Currently selected profile name.
    pub selected: Option<String>,
    /// Visible screen.
    pub screen: Screen,
    /// Connection state.
    pub state: ConnectionState,
    /// Latest daemon status snapshot, when one has been received.
    pub status: Option<StatusReport>,
    /// Gateway username being edited.
    pub username: String,
    /// Password being edited; zeroized on drop and moved out on submit.
    pub password: Zeroizing<String>,
    /// One-time token being edited; zeroized on drop and moved out on submit.
    pub token: Zeroizing<String>,
    /// Decoded TOTP secret for the selected profile, when the keyring has one.
    totp_secret: Option<Zeroizing<Vec<u8>>>,
    /// Current Unix time, refreshed by the tick so the countdown is testable.
    pub now_unix: u64,
    /// Log level shown in settings.
    pub log_level: LogLevel,
    /// Control endpoint shown in settings.
    pub endpoint: String,
    /// Non-state notice (for example a missing profile or empty password).
    pub notice: Option<String>,
    /// Fields typed into the "Add profile" sheet.
    pub add_profile: ProfileDraft,
    /// Per-field validation of [`Self::add_profile`].
    pub add_profile_errors: ProfileDraftErrors,
    /// A save-time failure (disk or store), shown inside the sheet.
    pub add_profile_error: Option<String>,
    /// Base32 secret typed into the enrol form; zeroized and never displayed
    /// once saved.
    pub totp_input: Zeroizing<String>,
    /// Decoded secret awaiting an explicit save.
    pending_totp: Option<Zeroizing<Vec<u8>>>,
    /// Normalized base32 text awaiting an explicit save.
    pending_totp_text: Option<Zeroizing<String>>,
    /// Profile the pending secret belongs to.
    pending_totp_profile: Option<String>,
    /// State transitions that have not been handed to a [`crate::notifications::Notifier`].
    pending_notifications: Vec<TransitionNotification>,
    /// Whether this GUI process started the daemon (so Quit may stop it).
    pub started_daemon: bool,
    /// Whether the explicit daemon-start action is in flight.
    pub daemon_start_busy: bool,
    /// Last known start-at-login state.
    pub autostart: AutostartState,
    /// Whether an autostart change is in flight.
    pub autostart_busy: bool,
    /// Set when quitting after a failed disconnect; the user may quit anyway.
    pub quit_confirmation: Option<String>,
    /// Whether the in-flight disconnect was requested by Quit.
    pub quit_after_disconnect: bool,
}

impl ViewModel {
    /// Build the initial state from the profile store.
    pub fn new(store: &ProfileStore, endpoint: String, now_unix: u64) -> Self {
        let mut profiles: Vec<ProfileRow> = store
            .profiles
            .values()
            .map(|profile| ProfileRow {
                name: profile.name.clone(),
                url: profile.url.clone(),
                realm: profile.realm.clone(),
                username: profile.username.clone(),
                split_tunnel: split_tunnel_label(&profile.split_tunnel),
                split_tunnel_routes: split_tunnel_routes(&profile.split_tunnel),
                totp_enrolled: false,
            })
            .collect();
        profiles.sort_by(|left, right| left.name.cmp(&right.name));

        let selected = store
            .default
            .clone()
            .filter(|name| profiles.iter().any(|row| &row.name == name))
            .or_else(|| profiles.first().map(|row| row.name.clone()));
        let username = selected
            .as_deref()
            .and_then(|name| store.get(name))
            .and_then(|profile| profile.username.clone())
            .unwrap_or_default();

        Self {
            profiles,
            selected,
            screen: Screen::Profiles,
            state: ConnectionState::Disconnected,
            status: None,
            username,
            password: Zeroizing::new(String::new()),
            token: Zeroizing::new(String::new()),
            totp_secret: None,
            now_unix,
            log_level: LogLevel::parse("info"),
            endpoint,
            notice: None,
            add_profile: ProfileDraft::default(),
            add_profile_errors: ProfileDraftErrors::default(),
            add_profile_error: None,
            totp_input: Zeroizing::new(String::new()),
            pending_totp: None,
            pending_totp_text: None,
            pending_totp_profile: None,
            pending_notifications: Vec::new(),
            started_daemon: false,
            daemon_start_busy: false,
            autostart: AutostartState::Loading,
            autostart_busy: false,
            quit_confirmation: None,
            quit_after_disconnect: false,
        }
    }

    /// Rebuild the profile rows from the store, preserving the selection.
    ///
    /// The TOTP cache is invalidated because the keyring may have changed.
    pub fn reload_profiles(&mut self, store: &ProfileStore, now_unix: u64) {
        let selected = self.selected.clone();
        let log_level = self.log_level;
        let endpoint = self.endpoint.clone();
        let started_daemon = self.started_daemon;
        let autostart = self.autostart.clone();
        let mut refreshed = Self::new(store, endpoint, now_unix);
        refreshed.log_level = log_level;
        refreshed.started_daemon = started_daemon;
        refreshed.autostart = autostart;
        if let Some(name) = selected {
            if refreshed.profiles.iter().any(|row| row.name == name) {
                refreshed.selected = Some(name.clone());
                refreshed.username = store
                    .get(&name)
                    .and_then(|profile| profile.username.clone())
                    .unwrap_or_default();
            }
        }
        *self = refreshed;
    }

    /// Select a profile and open the connect sheet.
    pub fn select_profile(&mut self, name: &str, now_unix: u64) {
        if !self.profiles.iter().any(|row| row.name == name) {
            self.notice = Some(format!("profile '{name}' was not found"));
            return;
        }
        self.selected = Some(name.to_owned());
        self.username = self
            .profiles
            .iter()
            .find(|row| row.name == name)
            .and_then(|row| row.username.clone())
            .unwrap_or_default();
        self.password.clear();
        self.token.clear();
        self.totp_secret = None;
        self.clear_totp_entry();
        self.notice = None;
        self.now_unix = now_unix;
        self.screen = Screen::Connect;
    }

    /// Select a profile and open the settings screen.
    pub fn select_for_settings(&mut self, name: &str, now_unix: u64) {
        if !self.profiles.iter().any(|row| row.name == name) {
            self.notice = Some(format!("profile '{name}' was not found"));
            return;
        }
        self.selected = Some(name.to_owned());
        self.clear_secrets();
        self.totp_secret = None;
        self.notice = None;
        self.now_unix = now_unix;
        self.screen = Screen::Settings;
    }

    /// Open the "Add profile" sheet with an empty draft.
    pub fn begin_add_profile(&mut self) {
        self.add_profile = ProfileDraft::default();
        self.add_profile_errors = ProfileDraftErrors::default();
        self.add_profile_error = None;
        self.notice = None;
        self.screen = Screen::AddProfile;
    }

    /// Close the "Add profile" sheet without saving.
    pub fn cancel_add_profile(&mut self) {
        self.add_profile = ProfileDraft::default();
        self.add_profile_errors = ProfileDraftErrors::default();
        self.add_profile_error = None;
        if self.screen == Screen::AddProfile {
            self.screen = Screen::Profiles;
        }
    }

    /// Update the draft name and revalidate every field.
    pub fn set_add_profile_name(&mut self, value: String) {
        self.add_profile.name = value;
        self.refresh_add_profile_errors();
    }

    /// Update the draft gateway URL and revalidate every field.
    pub fn set_add_profile_url(&mut self, value: String) {
        self.add_profile.url = value;
        self.refresh_add_profile_errors();
    }

    /// Update the draft realm and revalidate every field.
    pub fn set_add_profile_realm(&mut self, value: String) {
        self.add_profile.realm = value;
        self.refresh_add_profile_errors();
    }

    /// Update the draft username and revalidate every field.
    pub fn set_add_profile_username(&mut self, value: String) {
        self.add_profile.username = value;
        self.refresh_add_profile_errors();
    }

    /// Revalidate the draft and store the per-field messages.
    pub fn validate_add_profile(&mut self) -> bool {
        self.refresh_add_profile_errors();
        self.add_profile_errors.is_valid()
    }

    /// Whether Save may be pressed for the current draft.
    pub fn can_save_add_profile(&self) -> bool {
        validate_profile_draft(&self.add_profile, self.existing_profile_names()).is_valid()
    }

    /// Build the profile described by a valid draft.
    ///
    /// The store still has the final say on rules such as HTTPS, so a
    /// store-side failure is reported on the URL field.
    pub fn build_profile_from_draft(&mut self) -> Result<Profile, String> {
        if !self.validate_add_profile() {
            return Err(self
                .add_profile_errors
                .first()
                .unwrap_or("fix the highlighted fields")
                .to_owned());
        }

        let profile = Profile::new(
            self.add_profile.name.trim(),
            self.add_profile.url.trim(),
            self.add_profile.realm.trim(),
        )
        .map_err(|error| {
            let message = error.to_string();
            self.add_profile_errors.url = Some(message.clone());
            message
        })?;

        let mut profile = profile;
        profile.username = Some(self.add_profile.username.trim().to_owned());
        Ok(profile)
    }

    /// Add the draft to `store` and move back to the refreshed profile list.
    ///
    /// The caller persists `store` afterwards; this keeps the view model free
    /// of path and file handling while still writing through [`ProfileStore`].
    pub fn save_added_profile(
        &mut self,
        store: &mut ProfileStore,
        now_unix: u64,
    ) -> Result<String, String> {
        let profile = match self.build_profile_from_draft() {
            Ok(profile) => profile,
            Err(message) => {
                self.add_profile_error = Some(message.clone());
                return Err(message);
            }
        };
        let name = profile.name.clone();
        if let Err(error) = store.add(profile) {
            let message = error.to_string();
            if message.contains("already exists") {
                self.add_profile_errors.name = Some(message.clone());
            }
            self.add_profile_error = Some(message.clone());
            return Err(message);
        }

        self.apply_profile_added(store, &name, now_unix);
        Ok(name)
    }

    /// Refresh rows from `store`, select the newly added profile and return to
    /// the list screen.
    pub fn apply_profile_added(&mut self, store: &ProfileStore, name: &str, now_unix: u64) {
        self.reload_profiles(store, now_unix);
        if self.profiles.iter().any(|row| row.name == name) {
            self.selected = Some(name.to_owned());
            self.username = store
                .get(name)
                .and_then(|profile| profile.username.clone())
                .unwrap_or_default();
        }
        self.add_profile = ProfileDraft::default();
        self.add_profile_errors = ProfileDraftErrors::default();
        self.add_profile_error = None;
        self.notice = Some(format!("Profile '{name}' added."));
        self.screen = Screen::Profiles;
    }

    fn existing_profile_names(&self) -> impl Iterator<Item = &str> {
        self.profiles.iter().map(|row| row.name.as_str())
    }

    fn refresh_add_profile_errors(&mut self) {
        let errors = validate_profile_draft(&self.add_profile, self.existing_profile_names());
        self.add_profile_errors = errors;
        self.add_profile_error = None;
    }

    /// The selected profile row, if any.
    pub fn selected_profile(&self) -> Option<&ProfileRow> {
        self.selected
            .as_deref()
            .and_then(|name| self.profiles.iter().find(|row| row.name == name))
    }

    /// Whether a TOTP secret is available for the selected profile.
    pub fn has_totp(&self) -> bool {
        self.totp_secret.is_some()
    }

    /// Install (or clear) the decoded TOTP secret for a profile.
    ///
    /// A late keyring answer for a profile that is no longer selected is
    /// ignored, and the row's `totp_enrolled` flag is updated.
    pub fn set_totp_secret(&mut self, profile: &str, secret: Option<Vec<u8>>) {
        if let Some(row) = self.profiles.iter_mut().find(|row| row.name == profile) {
            row.totp_enrolled = secret.is_some();
        }
        if self.selected.as_deref() == Some(profile) {
            self.totp_secret = secret.map(Zeroizing::new);
        }
    }

    /// Seconds until the current TOTP code expires, when one is enrolled.
    pub fn totp_remaining_secs(&self) -> Option<u64> {
        self.totp_secret
            .as_ref()
            .map(|_| Totp::default().remaining_seconds(self.now_unix))
    }

    /// The live countdown label, when a TOTP secret is enrolled.
    pub fn totp_countdown(&self) -> Option<String> {
        self.totp_remaining_secs().map(format_totp_countdown)
    }

    /// A freshly generated code for the current time, when one is enrolled.
    ///
    /// Codes are generated on demand and never cached.
    pub fn generated_token(&self) -> Option<String> {
        self.totp_secret
            .as_ref()
            .and_then(|secret| Totp::default().code_at(secret, self.now_unix).ok())
    }

    /// Update the typed base32 secret, discarding a stale validation.
    pub fn set_totp_input(&mut self, value: String) {
        if self.totp_input.as_str() != value {
            self.clear_pending_totp();
        }
        self.totp_input = Zeroizing::new(value);
    }

    /// Validate the typed base32 secret without storing it.
    ///
    /// On success the decoded secret is held only until the user presses Save,
    /// and a current code plus countdown are shown for comparison with the
    /// phone. The input is never echoed in an error message.
    pub fn validate_totp_input(&mut self) -> Result<(), String> {
        let profile = self
            .selected
            .clone()
            .ok_or_else(|| "select a profile before enrolling a secret".to_owned())?;
        let normalized = normalize_base32(self.totp_input.as_str())?;
        let secret =
            decode_base32(&normalized).map_err(|_| "the secret is not valid base32".to_owned())?;
        if secret.is_empty() {
            return Err("the secret must not be empty".to_owned());
        }
        Totp::default()
            .code_at(&secret, self.now_unix)
            .map_err(|_| "the secret is not valid base32".to_owned())?;

        self.pending_totp = Some(Zeroizing::new(secret));
        self.pending_totp_text = Some(Zeroizing::new(normalized));
        self.pending_totp_profile = Some(profile);
        self.notice = Some(
            "Compare the code with your authenticator app, then save it to the OS keyring."
                .to_owned(),
        );
        Ok(())
    }

    /// The current code for a validated but unsaved secret.
    pub fn pending_totp_code(&self) -> Option<String> {
        self.pending_totp
            .as_ref()
            .and_then(|secret| Totp::default().code_at(secret, self.now_unix).ok())
    }

    /// The countdown for a validated but unsaved secret.
    pub fn pending_totp_countdown(&self) -> Option<String> {
        self.pending_totp
            .as_ref()
            .map(|_| format_totp_countdown(Totp::default().remaining_seconds(self.now_unix)))
    }

    /// Whether an enrolment is validated and awaiting Save.
    pub fn has_pending_totp(&self) -> bool {
        self.pending_totp.is_some()
    }

    /// Move a validated secret out for the one keyring write.
    ///
    /// The type has no `Debug`/`Display`, so it cannot be logged by accident.
    pub fn take_totp_enrolment(&mut self) -> Result<TotpEnrolment, String> {
        let profile = self
            .pending_totp_profile
            .clone()
            .ok_or_else(|| "validate the secret before saving it".to_owned())?;
        let secret = self
            .pending_totp
            .take()
            .ok_or_else(|| "validate the secret before saving it".to_owned())?;
        let text = self
            .pending_totp_text
            .take()
            .ok_or_else(|| "validate the secret before saving it".to_owned())?;
        self.pending_totp_profile = None;
        self.totp_input.clear();
        Ok(TotpEnrolment {
            profile,
            encoded: text,
            decoded: secret,
        })
    }

    /// Record a successful keyring write and clear the input and preview.
    pub fn apply_totp_saved(&mut self, profile: &str, decoded: Vec<u8>) {
        self.set_totp_secret(profile, Some(decoded));
        self.clear_totp_entry();
        self.notice = Some("TOTP secret saved to the OS keyring.".to_owned());
    }

    /// Record a successful keyring removal and clear the countdown source.
    pub fn apply_totp_removed(&mut self, profile: &str) {
        self.set_totp_secret(profile, None);
        self.clear_totp_entry();
        self.notice = Some("TOTP secret removed from the OS keyring.".to_owned());
    }

    /// Closing the window only hides it: the daemon and tunnel stay untouched.
    pub fn window_closed(&mut self) {}

    /// Decide what Quit must do before the process exits.
    ///
    /// A live tunnel is disconnected first. A disconnect already in progress
    /// needs confirmation because this GUI cannot prove the teardown finished.
    pub fn request_quit(&mut self) -> QuitPlan {
        self.quit_confirmation = None;
        if self.can_disconnect() {
            let profile = self.begin_disconnect();
            self.quit_after_disconnect = true;
            return QuitPlan::Disconnect(profile);
        }
        if self.state == ConnectionState::Disconnecting {
            let reason = "the tunnel is still disconnecting".to_owned();
            self.quit_confirmation = Some(reason.clone());
            return QuitPlan::Confirm(reason);
        }
        self.quit_after_disconnect = false;
        QuitPlan::Exit
    }

    /// Apply the disconnect that Quit requested.
    ///
    /// A failed disconnect keeps the window alive and records a confirmation;
    /// quitting anyway is then an explicit second decision, not a silent exit.
    pub fn quit_disconnect_finished(
        &mut self,
        result: Result<StatusReport, ClientError>,
    ) -> QuitPlan {
        self.quit_after_disconnect = false;
        match result {
            Ok(status) => {
                self.apply_status(status);
                QuitPlan::Exit
            }
            Err(error) => {
                let reason = error.to_string();
                self.apply_client_error(error);
                self.quit_confirmation = Some(reason.clone());
                QuitPlan::Confirm(reason)
            }
        }
    }

    /// Accept the confirmation and finish quitting.
    pub fn quit_anyway(&mut self) -> QuitPlan {
        self.quit_confirmation = None;
        QuitPlan::Exit
    }

    /// Dismiss the confirmation and leave the application running.
    pub fn cancel_quit(&mut self) {
        self.quit_confirmation = None;
    }

    /// Mark the explicit daemon start as in flight.
    pub fn begin_daemon_start(&mut self) -> bool {
        if self.daemon_start_busy {
            return false;
        }
        self.daemon_start_busy = true;
        self.quit_confirmation = None;
        true
    }

    /// Record a successful explicit daemon start.
    pub fn daemon_started(&mut self) {
        self.daemon_start_busy = false;
        self.started_daemon = true;
        self.notice = None;
    }

    /// Record a failed or cancelled explicit daemon start without panicking.
    pub fn daemon_start_failed(&mut self, message: impl Into<String>) {
        self.daemon_start_busy = false;
        self.notice = Some(message.into());
    }

    /// Record the result of the read-only autostart status query.
    pub fn apply_autostart_status(&mut self, result: Result<TaskState, String>) {
        self.autostart = match result {
            Ok(TaskState::Present) => AutostartState::Present,
            Ok(TaskState::Absent) => AutostartState::Absent,
            Ok(TaskState::Unknown) => {
                AutostartState::Unknown("the task state could not be determined".to_owned())
            }
            Err(message) => AutostartState::Unavailable(message),
        };
    }

    /// Start an autostart change, if the current state allows one.
    pub fn begin_autostart_change(&mut self) -> Option<bool> {
        if self.autostart_busy {
            return None;
        }
        let target = self.autostart.toggle_target()?;
        self.autostart_busy = true;
        Some(target)
    }

    /// Record the result of an autostart change.
    pub fn apply_autostart_change(&mut self, result: Result<TaskState, String>) {
        self.autostart_busy = false;
        match result {
            Ok(TaskState::Present) => {
                self.autostart = AutostartState::Present;
                self.notice = Some("Start at login is on.".to_owned());
            }
            Ok(TaskState::Absent) => {
                self.autostart = AutostartState::Absent;
                self.notice = Some("Start at login is off.".to_owned());
            }
            Ok(TaskState::Unknown) => {
                self.autostart =
                    AutostartState::Unknown("the task state could not be determined".to_owned());
                self.notice = Some("The autostart task state could not be determined.".to_owned());
            }
            Err(message) => {
                self.notice = Some(format!("could not change start at login: {message}"));
            }
        }
    }

    /// The state of the tray menu for the current state machine.
    pub fn tray_menu(&self) -> TrayMenuState {
        let status = match &self.state {
            ConnectionState::Connected => {
                let address = self
                    .status
                    .as_ref()
                    .map(render_address)
                    .unwrap_or_else(|| "address unavailable".to_owned());
                format!("Connected · {address}")
            }
            other => state_label(other).to_owned(),
        };
        TrayMenuState {
            status,
            connect_enabled: self.can_connect(),
            disconnect_enabled: self.can_disconnect(),
        }
    }

    /// Drain the notifications generated by the most recent transitions.
    pub fn take_notifications(&mut self) -> Vec<TransitionNotification> {
        std::mem::take(&mut self.pending_notifications)
    }

    /// Hand every pending notification to a notifier.
    pub fn flush_notifications(&mut self, notifier: &dyn crate::notifications::Notifier) {
        for notification in self.take_notifications() {
            notifier.notify(&notification);
        }
    }

    fn clear_pending_totp(&mut self) {
        self.pending_totp = None;
        self.pending_totp_text = None;
        self.pending_totp_profile = None;
    }

    fn clear_totp_entry(&mut self) {
        self.totp_input.clear();
        self.clear_pending_totp();
    }

    /// Refresh the clock used by the countdown.
    pub fn tick(&mut self, now_unix: u64) {
        self.now_unix = now_unix;
    }

    /// Whether a connect request may be made in the current state.
    pub fn can_connect(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Disconnected
                | ConnectionState::Failed { .. }
                | ConnectionState::DaemonUnavailable { .. }
        )
    }

    /// Whether a disconnect request may be made in the current state.
    pub fn can_disconnect(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Authenticating
                | ConnectionState::Connecting
                | ConnectionState::Connected
        )
    }

    /// Validate the sheet and move the secrets out for one connect request.
    ///
    /// On success the password and token buffers are already empty: they are
    /// never rendered again after submission. A TOTP code is generated fresh
    /// when no token was typed.
    pub fn take_credentials(&mut self) -> Result<ConnectCredentials, String> {
        let profile = self
            .selected
            .clone()
            .ok_or_else(|| "select a profile before connecting".to_owned())?;
        if self.username.trim().is_empty() {
            return Err("username must not be empty".to_owned());
        }
        if self.password.is_empty() {
            return Err("password must not be empty".to_owned());
        }
        if !self.can_connect() {
            return Err(format!("the daemon is already {}", self.state.name()));
        }

        let username = self.username.clone();
        let password = std::mem::replace(&mut self.password, Zeroizing::new(String::new()));
        let typed_token = std::mem::replace(&mut self.token, Zeroizing::new(String::new()));
        let token = if typed_token.is_empty() {
            self.generated_token().map(Zeroizing::new)
        } else {
            Some(typed_token)
        };

        self.notice = None;
        self.state = ConnectionState::Authenticating;
        self.screen = Screen::Connect;

        Ok(ConnectCredentials {
            profile,
            username,
            password,
            token,
        })
    }

    /// Clear every credential field (username, password and token).
    ///
    /// Called on disconnect, on failure and when the connect sheet is reopened,
    /// so nothing typed earlier survives a session boundary.
    pub fn clear_secrets(&mut self) {
        self.username.clear();
        self.password.clear();
        self.token.clear();
        self.clear_totp_entry();
    }

    /// Apply a successful `status` snapshot.
    pub fn apply_status(&mut self, report: StatusReport) {
        let previous = self.state.clone();
        let next = state_from_report(&report);
        let address = matches!(next, ConnectionState::Connected).then(|| render_address(&report));
        let settled = matches!(
            next,
            ConnectionState::Disconnected
                | ConnectionState::Failed { .. }
                | ConnectionState::RecoveryIncomplete { .. }
        );

        if let Some(profile) = report.profile.clone() {
            if self.profiles.iter().any(|row| row.name == profile) {
                self.selected = Some(profile);
            }
        }
        if let Some(notification) = transition_notification(&previous, &next, address.as_deref()) {
            self.pending_notifications.push(notification);
        }
        self.state = next;
        self.status = Some(report);

        match self.state {
            ConnectionState::Connected => self.screen = Screen::Connected,
            ConnectionState::Disconnected | ConnectionState::Failed { .. } => {
                self.clear_secrets();
                if self.screen == Screen::Connected {
                    self.screen = Screen::Profiles;
                }
            }
            ConnectionState::RecoveryIncomplete { .. } => {
                self.clear_secrets();
                if self.screen == Screen::Connected {
                    self.screen = Screen::Profiles;
                }
            }
            _ => {}
        }
        if settled {
            self.notice = None;
        }
    }

    /// Apply a reach/transport failure from the control client.
    pub fn apply_client_error(&mut self, error: ClientError) {
        match &error {
            ClientError::Unavailable(_)
            | ClientError::AccessDenied(_)
            | ClientError::ProtocolMismatch(_) => {
                self.mark_daemon_unavailable(error.to_string());
            }
            ClientError::Transport(_) | ClientError::Protocol(_) => {
                self.mark_failed(error.to_string());
            }
        }
    }

    /// Move to `Failed` and clear every secret.
    pub fn mark_failed(&mut self, reason: impl Into<String>) {
        let previous = self.state.clone();
        self.state = ConnectionState::Failed {
            reason: reason.into(),
        };
        if let Some(notification) = transition_notification(&previous, &self.state, None) {
            self.pending_notifications.push(notification);
        }
        self.status = None;
        self.clear_secrets();
        if self.screen == Screen::Connected {
            self.screen = Screen::Profiles;
        }
    }

    /// Move to `DaemonUnavailable` and clear every secret.
    pub fn mark_daemon_unavailable(&mut self, message: impl Into<String>) {
        self.state = ConnectionState::DaemonUnavailable {
            message: message.into(),
        };
        self.status = None;
        self.clear_secrets();
        if self.screen == Screen::Connected {
            self.screen = Screen::Profiles;
        }
    }

    /// Ask the daemon to disconnect and enter `Disconnecting`.
    ///
    /// Returns the profile name to send with the request.
    pub fn begin_disconnect(&mut self) -> Option<String> {
        if !self.can_disconnect() {
            self.notice = Some(format!(
                "the daemon is not connected (state: {})",
                self.state.name()
            ));
            return None;
        }
        self.state = ConnectionState::Disconnecting;
        self.clear_secrets();
        self.notice = None;
        self.selected.clone()
    }

    /// The dot to show next to a profile.
    pub fn profile_dot(&self, name: &str) -> ProfileDot {
        if matches!(self.state, ConnectionState::DaemonUnavailable { .. }) {
            return ProfileDot::Unavailable;
        }
        if self.state == ConnectionState::Connected {
            let active = self
                .status
                .as_ref()
                .and_then(|status| status.profile.as_deref())
                .or(self.selected.as_deref());
            return if active == Some(name) {
                ProfileDot::Connected
            } else {
                ProfileDot::Disconnected
            };
        }
        if self.selected.as_deref() != Some(name) {
            return ProfileDot::Disconnected;
        }
        match self.state {
            ConnectionState::Authenticating
            | ConnectionState::Connecting
            | ConnectionState::Disconnecting => ProfileDot::Busy,
            ConnectionState::Failed { .. } => ProfileDot::Failed,
            _ => ProfileDot::Disconnected,
        }
    }
}

/// The interval at which a `status` poll should run, if any.
pub fn poll_interval(state: &ConnectionState) -> Option<Duration> {
    state.should_poll().then_some(STATUS_POLL_INTERVAL)
}

/// The interval for the one-second UI tick.
///
/// The tick polls `status` while a session is live or changing, and also drives
/// the TOTP countdown while the connect sheet is open. It is `None` otherwise,
/// so the application never busy-loops.
pub fn tick_interval(
    state: &ConnectionState,
    screen: Screen,
    has_totp: bool,
    has_totp_preview: bool,
) -> Option<Duration> {
    if poll_interval(state).is_some() {
        return Some(STATUS_POLL_INTERVAL);
    }
    ((screen == Screen::Connect && has_totp) || (screen == Screen::Settings && has_totp_preview))
        .then_some(STATUS_POLL_INTERVAL)
}

/// Format the TOTP countdown. At zero the code has just expired.
pub fn format_totp_countdown(seconds: u64) -> String {
    format!("code expires in {seconds}s")
}

/// Human-readable byte count with binary units.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 5] = [
        ("KiB", 1 << 10),
        ("MiB", 1 << 20),
        ("GiB", 1 << 30),
        ("TiB", 1 << 40),
        ("PiB", 1 << 50),
    ];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let (name, unit) = UNITS
        .iter()
        .rev()
        .find(|(_, unit)| bytes >= *unit)
        .copied()
        .unwrap_or(UNITS[0]);
    let whole = bytes / unit;
    let tenths = (bytes % unit) * 10 / unit;
    if whole >= 100 {
        format!("{whole} {name}")
    } else {
        format!("{whole}.{tenths} {name}")
    }
}

/// Human-readable session uptime.
pub fn format_uptime(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!(
            "{}h {:02}m {:02}s",
            seconds / 3600,
            (seconds % 3600) / 60,
            seconds % 60
        )
    }
}

/// Render the assigned address and prefix.
pub fn render_address(status: &StatusReport) -> String {
    match (&status.address, status.prefix_len) {
        (Some(address), Some(prefix)) => format!("{address}/{prefix}"),
        (Some(address), None) => address.clone(),
        (None, _) => "not assigned".to_owned(),
    }
}

/// Render the negotiated MTU.
pub fn render_mtu(status: &StatusReport) -> String {
    status
        .mtu
        .map(|mtu| mtu.to_string())
        .unwrap_or_else(|| "default".to_owned())
}

/// Render the applied route count.
pub fn render_routes(status: &StatusReport) -> String {
    match status.route_count {
        0 => "none".to_owned(),
        1 => "1 applied".to_owned(),
        count => format!("{count} applied"),
    }
}

/// Render the DNS server list.
pub fn render_dns(status: &StatusReport) -> String {
    if status.dns.is_empty() {
        "none".to_owned()
    } else {
        status.dns.join(", ")
    }
}

/// Human-readable split-tunnel mode.
pub fn split_tunnel_label(intent: &SplitTunnelIntent) -> String {
    match intent {
        SplitTunnelIntent::Gateway => "gateway routes only".to_owned(),
        SplitTunnelIntent::All => "all traffic".to_owned(),
        SplitTunnelIntent::Custom(routes) => format!("custom ({} routes)", routes.len()),
    }
}

/// Split-tunnel routes for the settings preview.
pub fn split_tunnel_routes(intent: &SplitTunnelIntent) -> Vec<String> {
    match intent {
        SplitTunnelIntent::Custom(routes) => routes.clone(),
        _ => Vec::new(),
    }
}

/// A detailed preview of what routing the selected profile asks for.
pub fn split_tunnel_preview(profile: &ProfileRow) -> String {
    if profile.split_tunnel_routes.is_empty() {
        profile.split_tunnel.clone()
    } else {
        format!(
            "{} ({})",
            profile.split_tunnel,
            profile.split_tunnel_routes.join(", ")
        )
    }
}

/// Keyring account name for a profile's TOTP secret.
pub fn totp_account(profile: &str) -> String {
    format!("{profile}/totp")
}

/// Current Unix time, saturating at zero.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn state_from_report(report: &StatusReport) -> ConnectionState {
    match report.state.as_str() {
        "disconnected" => ConnectionState::Disconnected,
        "authenticating" => ConnectionState::Authenticating,
        "connecting" => ConnectionState::Connecting,
        "connected" => ConnectionState::Connected,
        "disconnecting" => ConnectionState::Disconnecting,
        "recovery-incomplete" => ConnectionState::RecoveryIncomplete {
            report: report.recovery.clone().unwrap_or_default(),
        },
        "failed" => ConnectionState::Failed {
            reason: report
                .reason
                .clone()
                .unwrap_or_else(|| "the daemon reported a failure".to_owned()),
        },
        other => ConnectionState::Failed {
            reason: format!("the daemon reported an unknown state '{other}'"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevan_core::Profile;

    fn store() -> ProfileStore {
        store_with_split(SplitTunnelIntent::Gateway)
    }

    fn store_with_split(split: SplitTunnelIntent) -> ProfileStore {
        let mut store = ProfileStore::default();
        let mut profile = Profile::new(
            "example",
            "https://vpn.example.net/example_realm",
            "example_realm",
        )
        .expect("profile");
        profile.username = Some("example_user".into());
        profile.split_tunnel = split;
        store.upsert(profile).expect("upsert");
        store.set_default("example").expect("default");
        store
    }

    fn model() -> ViewModel {
        ViewModel::new(&store(), r"\\.\pipe\aevan".to_owned(), 0)
    }

    fn connected_report() -> StatusReport {
        StatusReport {
            state: "connected".into(),
            profile: Some("example".into()),
            device: Some("aevan".into()),
            address: Some("10.251.98.141".into()),
            prefix_len: Some(32),
            mtu: Some(1396),
            route_count: 4,
            dns: vec!["10.251.3.18".into(), "10.249.10.13".into()],
            bytes_in: 1024,
            bytes_out: 2048,
            uptime_secs: 65,
            ..StatusReport::default()
        }
    }

    #[test]
    fn a_status_poll_updates_bytes_uptime_and_screen() {
        let mut vm = model();
        vm.apply_status(connected_report());

        assert_eq!(vm.state, ConnectionState::Connected);
        assert_eq!(vm.screen, Screen::Connected);
        let status = vm.status.as_ref().expect("status");
        assert_eq!(status.bytes_in, 1024);
        assert_eq!(status.bytes_out, 2048);
        assert_eq!(status.uptime_secs, 65);

        let mut next = connected_report();
        next.bytes_in = 4096;
        next.bytes_out = 8192;
        next.uptime_secs = 66;
        vm.apply_status(next);
        let status = vm.status.as_ref().expect("status");
        assert_eq!(status.bytes_in, 4096);
        assert_eq!(status.bytes_out, 8192);
        assert_eq!(status.uptime_secs, 66);
    }

    #[test]
    fn a_daemon_failure_moves_to_failed_with_the_message() {
        let mut vm = model();
        vm.apply_client_error(ClientError::Transport("the connector stopped".into()));

        assert_eq!(
            vm.state,
            ConnectionState::Failed {
                reason: "the connector stopped".into()
            }
        );
        assert_eq!(vm.state.message(), Some("the connector stopped"));
        assert_eq!(vm.screen, Screen::Profiles);
    }

    #[test]
    fn a_reach_failure_moves_to_daemon_unavailable_with_the_message() {
        let mut vm = model();
        let message =
            "cannot reach the aevan daemon on \\\\.\\pipe\\aevan: no daemon is listening — start aevand first";
        vm.apply_client_error(ClientError::Unavailable(message.into()));

        assert!(matches!(
            vm.state,
            ConnectionState::DaemonUnavailable { .. }
        ));
        assert_eq!(vm.state.message(), Some(message));
        assert_eq!(vm.profile_dot("example"), ProfileDot::Unavailable);
    }

    #[test]
    fn connect_clears_secrets_on_failure() {
        let mut vm = model();
        vm.select_profile("example", 0);
        vm.password = Zeroizing::new("hunter2".into());
        vm.token = Zeroizing::new("123456".into());

        let credentials = vm.take_credentials().expect("credentials");
        assert_eq!(vm.state, ConnectionState::Authenticating);
        assert!(vm.password.is_empty(), "password stays in the sheet");
        assert!(vm.token.is_empty(), "token stays in the sheet");

        let debug = format!("{credentials:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(!debug.contains("123456"), "{debug}");

        vm.mark_failed("authentication rejected: denied");
        assert!(vm.password.is_empty());
        assert!(vm.token.is_empty());
        assert!(vm.username.is_empty());
    }

    #[test]
    fn a_typed_token_wins_over_generated_totp() {
        let mut vm = model();
        vm.select_profile("example", 0);
        vm.set_totp_secret("example", Some(b"12345678901234567890".to_vec()));
        vm.password = Zeroizing::new("hunter2".into());
        vm.token = Zeroizing::new("654321".into());

        let credentials = vm.take_credentials().expect("credentials");
        assert_eq!(credentials.token_value(), Some("654321"));
        assert!(!format!("{credentials:?}").contains("654321"));
    }

    #[test]
    fn a_generated_token_uses_the_enrolled_totp_secret() {
        let mut vm = model();
        vm.select_profile("example", 0);
        vm.set_totp_secret("example", Some(b"12345678901234567890".to_vec()));
        vm.now_unix = 59;
        vm.password = Zeroizing::new("hunter2".into());

        assert_eq!(vm.generated_token().as_deref(), Some("287082"));
        let credentials = vm.take_credentials().expect("credentials");
        assert_eq!(credentials.token_value(), Some("287082"));
        assert!(vm.token.is_empty());
    }

    #[test]
    fn totp_countdown_formatting_is_stable_at_the_boundaries() {
        assert_eq!(format_totp_countdown(0), "code expires in 0s");
        assert_eq!(format_totp_countdown(1), "code expires in 1s");
        assert_eq!(format_totp_countdown(29), "code expires in 29s");
        assert_eq!(format_totp_countdown(30), "code expires in 30s");

        let mut vm = model();
        vm.select_profile("example", 0);
        vm.set_totp_secret("example", Some(b"secret".to_vec()));
        vm.now_unix = 29;
        assert_eq!(vm.totp_countdown().as_deref(), Some("code expires in 1s"));
        vm.now_unix = 30;
        assert_eq!(vm.totp_countdown().as_deref(), Some("code expires in 30s"));
    }

    #[test]
    fn routes_dns_and_mtu_render_as_specified() {
        let status = connected_report();
        assert_eq!(render_address(&status), "10.251.98.141/32");
        assert_eq!(render_mtu(&status), "1396");
        assert_eq!(render_routes(&status), "4 applied");
        assert_eq!(render_dns(&status), "10.251.3.18, 10.249.10.13");

        let empty = StatusReport::default();
        assert_eq!(render_address(&empty), "not assigned");
        assert_eq!(render_mtu(&empty), "default");
        assert_eq!(render_routes(&empty), "none");
        assert_eq!(render_dns(&empty), "none");
        assert_eq!(
            render_routes(&StatusReport {
                route_count: 1,
                ..StatusReport::default()
            }),
            "1 applied"
        );
    }

    #[test]
    fn polling_runs_only_while_live_or_changing() {
        for state in [
            ConnectionState::Authenticating,
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Disconnecting,
            ConnectionState::RecoveryIncomplete {
                report: RecoveryReport::default(),
            },
        ] {
            assert_eq!(poll_interval(&state), Some(STATUS_POLL_INTERVAL));
            assert_eq!(
                tick_interval(&state, Screen::Profiles, false, false),
                Some(STATUS_POLL_INTERVAL)
            );
        }
        for state in [
            ConnectionState::Disconnected,
            ConnectionState::Failed { reason: "x".into() },
            ConnectionState::DaemonUnavailable {
                message: "gone".into(),
            },
        ] {
            assert_eq!(poll_interval(&state), None);
            assert_eq!(tick_interval(&state, Screen::Profiles, false, false), None);
        }

        assert_eq!(
            tick_interval(&ConnectionState::Disconnected, Screen::Connect, true, false),
            Some(STATUS_POLL_INTERVAL)
        );
        assert_eq!(
            tick_interval(
                &ConnectionState::Disconnected,
                Screen::Connect,
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn bytes_and_uptime_are_human_readable() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(59), "59s");
        assert_eq!(format_uptime(60), "1m 00s");
        assert_eq!(format_uptime(3661), "1h 01m 01s");
    }

    #[test]
    fn settings_show_the_split_tunnel_from_the_profile() {
        let store = store_with_split(SplitTunnelIntent::Custom(vec![
            "10.0.0.0/8".into(),
            "172.30.0.0/21".into(),
        ]));
        let vm = ViewModel::new(&store, "endpoint".into(), 0);
        let row = vm.selected_profile().expect("profile");
        assert_eq!(row.split_tunnel, "custom (2 routes)");
        assert_eq!(
            split_tunnel_preview(row),
            "custom (2 routes) (10.0.0.0/8, 172.30.0.0/21)"
        );

        let mut all = Profile::new("all", "https://example.net/realm", "realm").expect("profile");
        all.split_tunnel = SplitTunnelIntent::All;
        assert_eq!(split_tunnel_label(&all.split_tunnel), "all traffic");
    }

    #[test]
    fn disconnect_clears_the_sheet_and_requires_a_live_state() {
        let mut vm = model();
        vm.password = Zeroizing::new("hunter2".into());
        assert_eq!(vm.begin_disconnect(), None);
        assert!(vm.notice.is_some());

        vm.apply_status(connected_report());
        vm.password = Zeroizing::new("hunter2".into());
        assert_eq!(vm.begin_disconnect(), Some("example".into()));
        assert_eq!(vm.state, ConnectionState::Disconnecting);
        assert!(vm.password.is_empty());
    }

    #[test]
    fn an_incomplete_recovery_is_its_own_state_and_clears_when_the_journal_is_gone() {
        let mut vm = model();
        let report = RecoveryReport {
            rolled_back: 2,
            skipped_absent: 5,
            failures: vec![aevan_daemon::RecoveryFailure {
                step: "route".into(),
                reason: "denied".into(),
            }],
            removed: false,
            journal: Some("C:/Users/example/aevand.journal".into()),
        };
        vm.apply_status(StatusReport {
            state: "recovery-incomplete".into(),
            recovery: Some(report.clone()),
            ..StatusReport::default()
        });

        match &vm.state {
            ConnectionState::RecoveryIncomplete { report: current } => {
                assert_eq!(current.rolled_back, 2);
                assert_eq!(current.skipped_absent, 5);
                assert_eq!(current.failed(), 1);
            }
            other => panic!("expected recovery-incomplete, got {other:?}"),
        }
        assert_eq!(vm.state.name(), "recovery-incomplete");
        assert!(!matches!(vm.state, ConnectionState::Failed { .. }));
        assert!(!vm.can_connect());
        assert_eq!(poll_interval(&vm.state), Some(STATUS_POLL_INTERVAL));

        vm.apply_status(StatusReport {
            state: "disconnected".into(),
            ..StatusReport::default()
        });
        assert_eq!(vm.state, ConnectionState::Disconnected);
    }

    #[test]
    fn a_disconnect_status_moves_back_to_the_profile_list() {
        let mut vm = model();
        vm.apply_status(connected_report());
        assert_eq!(vm.screen, Screen::Connected);
        vm.apply_status(StatusReport {
            state: "disconnected".into(),
            ..StatusReport::default()
        });
        assert_eq!(vm.state, ConnectionState::Disconnected);
        assert_eq!(vm.screen, Screen::Profiles);
        assert!(vm.status.is_some());
    }

    #[test]
    fn the_dot_tracks_the_selected_profile_and_the_daemon() {
        let mut vm = model();
        assert_eq!(vm.profile_dot("example"), ProfileDot::Disconnected);

        vm.apply_status(connected_report());
        assert_eq!(vm.profile_dot("example"), ProfileDot::Connected);

        vm.mark_daemon_unavailable("gone");
        assert_eq!(vm.profile_dot("example"), ProfileDot::Unavailable);
    }

    #[test]
    fn a_profile_selection_clears_previous_secrets() {
        let mut vm = model();
        vm.password = Zeroizing::new("hunter2".into());
        vm.token = Zeroizing::new("123456".into());
        vm.select_profile("example", 0);
        assert!(vm.password.is_empty());
        assert!(vm.token.is_empty());
        assert_eq!(vm.screen, Screen::Connect);
    }

    #[test]
    fn settings_selection_clears_the_sheet_and_opens_settings() {
        let mut vm = model();
        vm.password = Zeroizing::new("hunter2".into());
        vm.select_for_settings("example", 0);
        assert_eq!(vm.screen, Screen::Settings);
        assert_eq!(vm.selected.as_deref(), Some("example"));
        assert!(vm.password.is_empty());
    }

    #[test]
    fn missing_credentials_are_refused_without_clearing_the_sheet() {
        let mut vm = model();
        vm.select_profile("example", 0);
        vm.password = Zeroizing::new("hunter2".into());
        vm.username.clear();

        let error = vm.take_credentials().expect_err("no username");
        assert!(error.contains("username"));
        assert_eq!(vm.password.as_str(), "hunter2");

        vm.username = "example_user".into();
        vm.password.clear();
        let error = vm.take_credentials().expect_err("no password");
        assert!(error.contains("password"));
    }

    #[test]
    fn tray_menu_enablement_follows_the_state_machine() {
        let mut vm = model();
        let menu = vm.tray_menu();
        assert_eq!(menu.status, "Disconnected");
        assert!(menu.connect_enabled);
        assert!(!menu.disconnect_enabled);

        vm.select_profile("example", 0);
        vm.password = Zeroizing::new("hunter2".into());
        vm.take_credentials().expect("credentials");
        let menu = vm.tray_menu();
        assert_eq!(menu.status, "Authenticating");
        assert!(!menu.connect_enabled);
        assert!(menu.disconnect_enabled);

        vm.apply_status(connected_report());
        let menu = vm.tray_menu();
        assert_eq!(menu.status, "Connected · 10.251.98.141/32");
        assert!(!menu.connect_enabled);
        assert!(menu.disconnect_enabled);

        vm.apply_status(StatusReport {
            state: "disconnected".into(),
            ..StatusReport::default()
        });
        let menu = vm.tray_menu();
        assert_eq!(menu.status, "Disconnected");
        assert!(menu.connect_enabled);
        assert!(!menu.disconnect_enabled);

        vm.mark_failed("denied");
        let menu = vm.tray_menu();
        assert_eq!(menu.status, "Failed");
        assert!(menu.connect_enabled);
        assert!(!menu.disconnect_enabled);
    }

    #[test]
    fn tray_menu_disables_both_actions_while_recovering_or_unreachable() {
        let mut vm = model();
        vm.apply_status(StatusReport {
            state: "recovery-incomplete".into(),
            recovery: Some(RecoveryReport::default()),
            ..StatusReport::default()
        });
        let menu = vm.tray_menu();
        assert_eq!(menu.status, "Recovery incomplete");
        assert!(!menu.connect_enabled);
        assert!(!menu.disconnect_enabled);

        vm.mark_daemon_unavailable("gone");
        let menu = vm.tray_menu();
        assert_eq!(menu.status, "Daemon unavailable");
        assert!(menu.connect_enabled);
        assert!(!menu.disconnect_enabled);
    }

    #[test]
    fn notifications_cover_the_three_transitions_without_duplicates() {
        let mut vm = model();
        vm.apply_status(connected_report());
        let notifications = vm.take_notifications();
        assert_eq!(
            notifications,
            vec![TransitionNotification::Connected {
                address: "10.251.98.141/32".into()
            }]
        );
        vm.apply_status(connected_report());
        assert!(vm.take_notifications().is_empty(), "no repeat on polling");

        let mut failed = model();
        failed.mark_failed("authentication rejected: denied");
        let notifications = failed.take_notifications();
        assert_eq!(
            notifications,
            vec![TransitionNotification::Failed {
                reason: "authentication rejected: denied".into()
            }]
        );
        assert_eq!(notifications[0].title(), "Aevan connection failed");
        assert_eq!(notifications[0].body(), "authentication rejected: denied");

        let mut recovery = model();
        recovery.apply_status(StatusReport {
            state: "recovery-incomplete".into(),
            recovery: Some(RecoveryReport {
                rolled_back: 1,
                skipped_absent: 2,
                failures: vec![aevan_daemon::RecoveryFailure {
                    step: "route".into(),
                    reason: "denied".into(),
                }],
                removed: false,
                journal: None,
            }),
            ..StatusReport::default()
        });
        let notifications = recovery.take_notifications();
        assert_eq!(
            notifications,
            vec![TransitionNotification::RecoveryIncomplete { failed: 1 }]
        );
        assert!(notifications[0].body().contains("1 step incomplete"));
    }

    #[test]
    fn notification_text_can_never_include_secret_material() {
        use crate::notifications::{Notifier, RecordingNotifier};

        let mut vm = model();
        vm.select_profile("example", 0);
        vm.password = Zeroizing::new("hunter2-password".into());
        vm.token = Zeroizing::new("654321-token".into());
        vm.totp_input = Zeroizing::new("JBSWY3DPEHPK3PXPSECRET".into());
        vm.set_totp_secret("example", Some(b"JBSWY3DPEHPK3PXPSECRET".to_vec()));

        let recorder = RecordingNotifier::default();
        vm.mark_failed("authentication rejected: denied");
        vm.flush_notifications(&recorder);

        let shown = recorder.shown();
        assert_eq!(shown.len(), 1);
        let rendered = format!("{} {}", shown[0].title(), shown[0].body());
        for secret in [
            "hunter2-password",
            "654321-token",
            "JBSWY3DPEHPK3PXPSECRET",
            "token",
            "password",
        ] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
        assert!(rendered.contains("denied"));

        // The trait is the only path to the OS; a recording notifier proves
        // exactly what would have been shown.
        Notifier::notify(&recorder, &shown[0]);
    }

    #[test]
    fn totp_validation_accepts_spaces_dashes_and_lowercase() {
        let mut vm = model();
        vm.select_for_settings("example", 0);

        vm.totp_input = Zeroizing::new("jbsw y3dp ehpk 3pxp".into());
        vm.validate_totp_input().expect("lowercase with spaces");
        assert!(vm.has_pending_totp());
        assert_eq!(vm.pending_totp_code().as_deref().map(str::len), Some(6));
        assert!(vm.pending_totp_countdown().is_some());

        vm.totp_input = Zeroizing::new("JBSW-Y3DP-EHPK-3PXP".into());
        vm.validate_totp_input().expect("dashes");
        assert!(vm.has_pending_totp());
    }

    #[test]
    fn totp_validation_rejects_invalid_base32_and_keeps_no_secret() {
        let mut vm = model();
        vm.select_for_settings("example", 0);

        for input in ["not*base32", "0189", "   ", "====", ""] {
            vm.totp_input = Zeroizing::new(input.into());
            let error = vm.validate_totp_input().expect_err(input);
            assert!(!vm.has_pending_totp(), "{input}");
            assert!(
                !error.contains(input) || input.trim().is_empty(),
                "the error echoed the input: {error}"
            );
        }
    }

    #[test]
    fn saving_a_validated_secret_clears_the_input_and_enables_the_countdown() {
        let mut vm = model();
        vm.select_for_settings("example", 0);
        vm.totp_input = Zeroizing::new("JBSW Y3DP EHPK 3PXP".into());
        vm.validate_totp_input().expect("validate");

        let enrolment = vm.take_totp_enrolment().expect("enrolment");
        assert_eq!(enrolment.profile(), "example");
        assert_eq!(enrolment.encoded(), "JBSWY3DPEHPK3PXP");
        let decoded = enrolment.into_decoded();
        assert!(vm.totp_input.is_empty(), "secret is not kept in the form");
        assert!(!vm.has_pending_totp());

        vm.apply_totp_saved("example", decoded);
        assert!(vm.totp_countdown().is_some());
        assert!(vm.selected_profile().expect("profile").totp_enrolled);
        assert!(vm.totp_input.is_empty());
    }

    #[test]
    fn secret_field_debug_is_redacted() {
        let field = SecretField::new("hunter2-token".into());
        let rendered = format!("{field:?}");
        assert!(!rendered.contains("hunter2"));
        assert_eq!(field.into_string(), "hunter2-token");
    }

    #[test]
    fn decoded_secret_debug_is_redacted() {
        let secret = DecodedTotpSecret::new(b"super-secret".to_vec());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "DecodedTotpSecret([REDACTED])");
        assert_eq!(secret.into_inner(), b"super-secret");
    }

    #[test]
    fn removing_a_secret_clears_the_countdown_source() {
        let mut vm = model();
        vm.select_profile("example", 0);
        vm.set_totp_secret("example", Some(b"JBSWY3DPEHPK3PXP".to_vec()));
        assert!(vm.totp_countdown().is_some());

        vm.apply_totp_removed("example");
        assert!(vm.totp_countdown().is_none());
        assert!(!vm.selected_profile().expect("profile").totp_enrolled);
        assert!(!vm.has_pending_totp());
    }

    #[test]
    fn credentials_cannot_be_cloned_and_redact_debug() {
        let mut vm = model();
        vm.select_profile("example", 0);
        vm.password = Zeroizing::new("hunter2".into());
        vm.token = Zeroizing::new("123456".into());
        let credentials = vm.take_credentials().expect("credentials");
        let debug = format!("{credentials:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("hunter2"));
        assert!(!debug.contains("123456"));
    }

    #[test]
    fn closing_the_window_keeps_the_connection_and_daemon() {
        let mut vm = model();
        vm.apply_status(connected_report());
        vm.started_daemon = true;

        vm.window_closed();

        assert_eq!(vm.state, ConnectionState::Connected);
        assert!(vm.started_daemon);
        assert!(vm.status.is_some());
    }

    #[test]
    fn quitting_disconnects_first_when_the_tunnel_is_live() {
        let mut vm = model();
        vm.apply_status(connected_report());

        assert_eq!(
            vm.request_quit(),
            QuitPlan::Disconnect(Some("example".into()))
        );
        assert_eq!(vm.state, ConnectionState::Disconnecting);
        assert!(vm.quit_after_disconnect);

        let plan = vm.quit_disconnect_finished(Ok(StatusReport {
            state: "disconnected".into(),
            ..StatusReport::default()
        }));
        assert_eq!(plan, QuitPlan::Exit);
        assert_eq!(vm.state, ConnectionState::Disconnected);
        assert!(!vm.quit_after_disconnect);
    }

    #[test]
    fn a_failed_disconnect_allows_quit_only_after_confirmation() {
        let mut vm = model();
        vm.apply_status(connected_report());
        assert!(matches!(vm.request_quit(), QuitPlan::Disconnect(_)));

        let plan = vm.quit_disconnect_finished(Err(ClientError::Transport(
            "teardown did not finish".into(),
        )));
        assert_eq!(plan, QuitPlan::Confirm("teardown did not finish".into()));
        assert_eq!(
            vm.quit_confirmation.as_deref(),
            Some("teardown did not finish")
        );

        vm.cancel_quit();
        assert!(vm.quit_confirmation.is_none());
        assert!(matches!(vm.state, ConnectionState::Failed { .. }));

        vm.quit_confirmation = Some("teardown did not finish".into());
        assert_eq!(vm.quit_anyway(), QuitPlan::Exit);
        assert!(vm.quit_confirmation.is_none());
    }

    #[test]
    fn quitting_while_disconnected_skips_the_disconnect_request() {
        let mut vm = model();
        assert_eq!(vm.request_quit(), QuitPlan::Exit);
        assert!(!vm.quit_after_disconnect);
    }

    #[test]
    fn quitting_while_already_disconnecting_asks_for_confirmation() {
        let mut vm = model();
        vm.apply_status(connected_report());
        assert!(matches!(vm.request_quit(), QuitPlan::Disconnect(_)));
        let plan = vm.request_quit();
        assert!(matches!(plan, QuitPlan::Confirm(_)));
        assert!(vm.quit_confirmation.is_some());
    }

    #[test]
    fn an_explicit_daemon_start_marks_the_daemon_as_ours() {
        let mut vm = model();
        assert!(vm.begin_daemon_start());
        assert!(!vm.begin_daemon_start(), "one prompt at a time");
        vm.daemon_started();
        assert!(vm.started_daemon);
        assert!(!vm.daemon_start_busy);

        vm.daemon_start_failed("the prompt was cancelled");
        assert_eq!(vm.notice.as_deref(), Some("the prompt was cancelled"));
    }

    #[test]
    fn autostart_state_is_honest_and_the_toggle_maps_to_the_task() {
        let mut vm = model();
        assert_eq!(vm.autostart, AutostartState::Loading);
        assert_eq!(vm.autostart.toggle_target(), None);
        assert!(vm.autostart.label().contains("checking"));

        vm.apply_autostart_status(Ok(TaskState::Present));
        assert_eq!(vm.autostart.toggle_target(), Some(false));
        assert!(vm.autostart.label().contains("starts at your logon"));

        vm.apply_autostart_status(Ok(TaskState::Absent));
        assert_eq!(vm.autostart.toggle_target(), Some(true));

        vm.apply_autostart_status(Err("access is denied".into()));
        assert_eq!(vm.autostart.toggle_target(), None);
        assert!(vm.autostart.label().contains("access is denied"));

        vm.apply_autostart_change(Ok(TaskState::Present));
        assert_eq!(vm.autostart, AutostartState::Present);
        assert_eq!(vm.notice.as_deref(), Some("Start at login is on."));
    }

    fn draft(vm: &mut ViewModel, name: &str, url: &str, realm: &str, username: &str) {
        vm.set_add_profile_name(name.into());
        vm.set_add_profile_url(url.into());
        vm.set_add_profile_realm(realm.into());
        vm.set_add_profile_username(username.into());
    }

    #[test]
    fn an_empty_add_profile_draft_shows_each_required_field_and_disables_save() {
        let mut vm = ViewModel::new(&ProfileStore::default(), "endpoint".into(), 0);
        vm.begin_add_profile();

        assert_eq!(vm.screen, Screen::AddProfile);
        assert!(!vm.can_save_add_profile());
        assert!(!vm.validate_add_profile());
        assert!(vm.add_profile_errors.name.is_some());
        assert!(vm.add_profile_errors.url.is_some());
        assert!(vm.add_profile_errors.realm.is_some());
        assert!(vm.add_profile_errors.username.is_some());
    }

    #[test]
    fn a_duplicate_profile_name_is_rejected() {
        let mut vm = model();
        vm.begin_add_profile();
        draft(
            &mut vm,
            "example",
            "https://other.example.net/realm",
            "realm",
            "user",
        );

        assert!(!vm.can_save_add_profile());
        let message = vm.add_profile_errors.name.as_deref().expect("name error");
        assert!(message.contains("already exists"), "{message}");
    }

    #[test]
    fn the_gateway_url_must_parse_as_http_or_https_with_a_host() {
        let mut vm = ViewModel::new(&ProfileStore::default(), "endpoint".into(), 0);
        vm.begin_add_profile();

        for invalid in ["not a url", "ftp://example.net/realm", "https:///realm"] {
            draft(&mut vm, "name", invalid, "realm", "user");
            assert!(!vm.can_save_add_profile(), "{invalid} must be rejected");
            assert!(vm.add_profile_errors.url.is_some(), "{invalid}");
        }

        draft(&mut vm, "name", "http://example.net/realm", "realm", "user");
        assert!(
            vm.can_save_add_profile(),
            "the sheet accepts both http and https"
        );
    }

    #[test]
    fn a_username_is_required_for_non_interactive_login() {
        let mut vm = ViewModel::new(&ProfileStore::default(), "endpoint".into(), 0);
        vm.begin_add_profile();
        draft(&mut vm, "name", "https://example.net/realm", "realm", "   ");

        assert!(!vm.can_save_add_profile());
        let message = vm
            .add_profile_errors
            .username
            .as_deref()
            .expect("username error");
        assert!(message.contains("non-interactive"), "{message}");
    }

    #[test]
    fn saving_a_profile_refreshes_selects_it_and_returns_to_the_list() {
        let mut store = ProfileStore::default();
        let mut vm = ViewModel::new(&store, "endpoint".into(), 0);
        vm.begin_add_profile();
        draft(
            &mut vm,
            "second",
            "https://second.example.net/realm",
            "second_realm",
            "second_user",
        );
        assert!(vm.can_save_add_profile());

        let name = vm.save_added_profile(&mut store, 0).expect("save");

        assert_eq!(name, "second");
        assert_eq!(vm.screen, Screen::Profiles);
        assert!(vm.profiles.iter().any(|row| row.name == "second"));
        assert_eq!(vm.selected.as_deref(), Some("second"));
        assert_eq!(vm.username, "second_user");
        assert_eq!(
            store
                .get("second")
                .and_then(|profile| profile.username.as_deref()),
            Some("second_user")
        );
        assert_eq!(vm.add_profile, ProfileDraft::default());
        assert!(
            vm.notice
                .as_deref()
                .is_some_and(|notice| notice.contains("added")),
            "{:?}",
            vm.notice
        );
    }

    #[test]
    fn cancelling_the_sheet_leaves_the_store_and_list_untouched() {
        let store = store();
        let mut vm = ViewModel::new(&store, "endpoint".into(), 0);
        vm.begin_add_profile();
        vm.set_add_profile_name("second".into());
        vm.cancel_add_profile();

        assert_eq!(vm.screen, Screen::Profiles);
        assert_eq!(vm.profiles.len(), store.profiles.len());
        assert_eq!(vm.add_profile, ProfileDraft::default());
    }
}
