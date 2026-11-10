#![deny(unsafe_code)]
//! Network Connect transport.
//!
//! This crate implements stages 1–3 of the NC transport as typed, testable units:
//!
//! * [`auth::AuthProbe`] — TLS, redirects and form-shape detection, no
//!   credentials.
//! * [`login::LoginRequest`] / [`login::LoginOutcome`] — exactly one credential
//!   POST and its classification; [`login::TokenRequest`] is the single token
//!   continuation.
//! * [`ncp::NcpConfig`] — the binary oNCP/KMP/TLV configuration as a typed
//!   value, including the TLS record/KMP framing decoder.
//! * [`oncp`] — byte builders and parsers for the post-login oNCP handshake,
//!   including the KMP 302 ESP negotiation and a live TLS session that stays
//!   open for it.
//! * [`esp::EspSession`] — the live ESP data plane over caller-supplied UDP and
//!   tunnel-device interfaces.
//!
//! Teardown lives in `aevan-tun` and `aevan-cli`. No type in this crate contains a
//! retry loop, a fallback host or a profile switch.

pub mod auth;
pub mod esp;
pub mod login;
pub mod ncp;
pub mod oncp;
pub mod replay;
pub mod secret;

use std::sync::{Mutex, OnceLock};

use aevan_core::{AevanError, AevanResult};

pub use auth::{
    detect_forms, AuthObservation, AuthProbe, FormDetection, FormShape, DEFAULT_MAX_REDIRECTS,
    DEFAULT_TIMEOUT,
};
pub use esp::{
    decrypt_packet, encrypt_packet, encrypt_packet_into, keepalive_packet, peek_sequence, peek_spi,
    DecryptedPacket, DecryptedPacketView, EspDevice, EspError, EspKeys, EspReadiness, EspSession,
    EspSessionConfig, EspSessionError, EspSessionMaterial, EspUdp, InboundSa, KeepaliveState,
    KmpChannel, OutboundSa, PollReport, ReceivedKmp, RekeyPolicy, RekeyReason, UdpEspTransport,
    ESP_BATCH_MAX, ESP_HEADER_LEN, ESP_IV_LEN, NEXT_HEADER_IPV4, NEXT_HEADER_IPV6,
    NEXT_HEADER_LZO_IPV4,
};
pub use login::{
    complete_continuation, ContinuationChallenge, ContinuationError, ContinuationExchange,
    ContinuationHop, ContinuationObservation, ContinuationRequest, LoginContext, LoginOutcome,
    LoginRequest, LoginSubmission, TokenChallenge, TokenRequest, CONTINUE_VALUE, FORM_CONTENT_TYPE,
};
pub use ncp::{
    decode_attributes, decode_flat_attributes, decode_grouped_attributes, decode_kmp_message,
    looks_like_kmp, AssignedV4, AssignedV6, Attribute, EspAuthentication, EspCompression,
    EspEncryption, EspKeyBlock, EspProposal, KmpMessage, NcpConfig, NcpError, Route,
    UnknownAttribute, KMP_CLIENT_CONFIG, KMP_CONFIG, KMP_ESP_NEGOTIATION,
};
pub use oncp::{
    client_config_reply, esp_initial_iv, esp_negotiation, handshake, handshake_live,
    handshake_live_once, handshake_live_session, handshake_once, handshake_request,
    handshake_request_with_content_length, hostname_packet, parse_esp_negotiation,
    ContentLengthVariant, EspLocalKeys, EspNegotiation, HandshakeAttempt, HandshakeError,
    HandshakeFrame, HandshakeIo, HandshakeOutcome, KmpFrame, KmpMessageOwned, LiveHandshake,
    OncpError, ESP_KEY_BLOCK_LEN, HANDSHAKE_CONTENT_LENGTH, HANDSHAKE_TARGET, HANDSHAKE_USER_AGENT,
};
pub use replay::{ReplayError, ReplayWindow, WINDOW_BITS};
pub use secret::SecretKey;

/// Milestone that will implement the data plane.
pub const MILESTONE: &str = "M2";

static LAST_LOGIN_NCP: OnceLock<Mutex<Option<NcpConfig>>> = OnceLock::new();

fn last_login_slot() -> &'static Mutex<Option<NcpConfig>> {
    LAST_LOGIN_NCP.get_or_init(|| Mutex::new(None))
}

/// Remember the NCP configuration parsed from a successful login in this
/// process. `aevan config` without `--from-file` reads it back.
pub fn remember_ncp_config(config: NcpConfig) {
    let mut slot = last_login_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = Some(config);
}

/// The NCP configuration from the last successful login in this process.
pub fn last_ncp_config() -> Option<NcpConfig> {
    last_login_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Forget the cached NCP configuration.
pub fn clear_last_ncp_config() {
    let mut slot = last_login_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = None;
}

/// Placeholder for the connect entry point (M2).
pub fn connect() -> AevanResult<()> {
    Err(AevanError::Unimplemented("aevan-nc data plane (M2)"))
}
