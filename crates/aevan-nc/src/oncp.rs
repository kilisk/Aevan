//! oNCP handshake framing and live handshake session.
//!
//! Network Connect performs an HTTP login first, then switches the same TLS
//! stream to the binary oNCP protocol. This module owns the byte builders and
//! parsers, plus [`handshake_live_session`], which keeps the TLS stream open so
//! the KMP 302/303 replies can be written after KMP 301.
//!
//! ## Handshake sequence (from the reference layout, `oncp.c`)
//!
//! 1. [`handshake_request`] builds the `POST /dana/js?prot=1&svc=4` request.
//!    `Connection: close` is required even though the TLS stream stays open; it
//!    tells the gateway to stop speaking HTTP. `Content-Length: 256` is fixed
//!    by the reference, not the actual length of the following packet.
//! 2. [`hostname_packet`] builds the little-endian length-prefixed hostname
//!    packet sent immediately after the request.
//! 3. The gateway answers with three bytes (length + status) and then a KMP 301
//!    configuration message. [`KmpFrame`] parses the record/KMP framing.
//! 4. [`esp_negotiation`] builds the KMP 302 reply carrying our inbound SPI and
//!    a freshly generated 0x40-byte key block. [`parse_esp_negotiation`] parses
//!    the same layout from a gateway/rekey message.
//! 5. [`client_config_reply`] builds the KMP 303 reply that carries the MTU the
//!    client accepted (group 6, attribute 2).
//!
//! The layout is read from openconnect's `oncp.c` (LGPL-2.1). The code here is
//! written independently; constants marked *reference* are copied from that
//! byte layout, and nothing depends on a live gateway.
//!
//! ## Secrets
//!
//! A KMP 302 payload contains live ESP keys. [`KmpFrame`]'s `Debug` prints only
//! framing facts, and [`EspNegotiation`] and [`EspLocalKeys`] store keys in
//! [`SecretKey`] values. Nothing here logs, serialises or formats key bytes.
//! `FallbackRng` documents the entropy fallback used when no random-number
//! dependency is available.

use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::{Digest, Sha1};

use aevan_proto::{ProtoError, RawTls, Url};

use crate::ncp::{
    decode_grouped_attributes, EspAuthentication, EspEncryption, NcpError, KMP_CLIENT_CONFIG,
    KMP_CONFIG, KMP_ESP_NEGOTIATION,
};
use crate::secret::SecretKey;

/// Request target for the post-login oNCP handshake.
pub const HANDSHAKE_TARGET: &str = "/dana/js?prot=1&svc=4";
/// Fixed `Content-Length` the reference sends with the handshake request.
pub const HANDSHAKE_CONTENT_LENGTH: usize = 256;

/// Fixed head of the hostname packet (reference `authpkt_head`).
const AUTH_PACKET_HEAD: [u8; 5] = [0x00, 0x04, 0x00, 0x00, 0x00];
/// Fixed tail of the hostname packet (reference `authpkt_tail`).
const AUTH_PACKET_TAIL: [u8; 6] = [0xbb, 0x01, 0x00, 0x00, 0x00, 0x00];

/// Two-byte little-endian TLS-record prefix.
const RECORD_PREFIX_LEN: usize = 2;
/// KMP header length, excluding the record prefix.
const KMP_HEADER_LEN: usize = 20;
/// Six zero bytes at the start of every KMP header.
const KMP_HEAD: [u8; 6] = [0x00; 6];
/// Inbound KMP tag, bytes `+8..+18` (reference `kmp_tail`).
const KMP_TAIL_IN: [u8; 10] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// Outbound KMP tag, bytes `+8..+18` (reference `kmp_tail_out`).
const KMP_TAIL_OUT: [u8; 10] = [0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];

/// Length of the 0x40-byte ESP key block in KMP 302.
pub const ESP_KEY_BLOCK_LEN: usize = 0x40;

/// Build the HTTP request that starts the oNCP handshake.
///
/// `host_header` is used verbatim in the `Host:` header, so pass `host:port`
/// when the port is not 443. `cookies` are written as one `Cookie:` header in
/// the supplied order. Header values containing CR or LF are rejected rather
/// than allowing request splitting.
pub fn handshake_request(
    host_header: &str,
    user_agent: &str,
    cookies: &[(String, String)],
) -> Result<Vec<u8>, OncpError> {
    check_header_value(host_header)?;
    check_header_value(user_agent)?;
    for (name, value) in cookies {
        check_header_value(name)?;
        check_header_value(value)?;
        if name.is_empty() || name.contains('=') || name.contains(';') {
            return Err(OncpError::InvalidHeader("cookie name".into()));
        }
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"POST ");
    out.extend_from_slice(HANDSHAKE_TARGET.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host_header.as_bytes());
    out.extend_from_slice(b"\r\nUser-Agent: ");
    out.extend_from_slice(user_agent.as_bytes());
    out.extend_from_slice(b"\r\n");
    if !cookies.is_empty() {
        out.extend_from_slice(b"Cookie: ");
        for (index, (name, value)) in cookies.iter().enumerate() {
            if index != 0 {
                out.extend_from_slice(b"; ");
            }
            out.extend_from_slice(name.as_bytes());
            out.push(b'=');
            out.extend_from_slice(value.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Content-Length: ");
    out.extend_from_slice(HANDSHAKE_CONTENT_LENGTH.to_string().as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    Ok(out)
}

/// Build the handshake request for a caller-selected `Content-Length`.
///
/// The live handshake needs a `Content-Length` that matches the hostname
/// packet it actually writes. The reference sends a fixed 256, so the driver
/// tries 256 first and falls back to the actual length.
/// `cookie_header` is the complete `Cookie:` value from the caller's session;
/// it is written verbatim after CR/LF validation.
pub fn handshake_request_with_content_length(
    host_header: &str,
    user_agent: &str,
    cookie_header: Option<&str>,
    content_length: usize,
) -> Result<Vec<u8>, OncpError> {
    check_header_value(host_header)?;
    check_header_value(user_agent)?;
    if let Some(cookie) = cookie_header {
        check_header_value(cookie)?;
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"POST ");
    out.extend_from_slice(HANDSHAKE_TARGET.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host_header.as_bytes());
    out.extend_from_slice(b"\r\nUser-Agent: ");
    out.extend_from_slice(user_agent.as_bytes());
    out.extend_from_slice(b"\r\n");
    if let Some(cookie) = cookie_header {
        out.extend_from_slice(b"Cookie: ");
        out.extend_from_slice(cookie.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    // The reference's oncp_common_headers appends this after Host, User-Agent
    // and Cookie. Without it the gateway answers the oNCP request with HTTP 200,
    // `NCP-Version: 3` and a three-byte body `00 00 01` — status byte 1.
    out.extend_from_slice(b"NCP-Version: 3\r\n");
    out.extend_from_slice(b"Content-Length: ");
    out.extend_from_slice(content_length.to_string().as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    Ok(out)
}

/// Build the hostname packet sent after the handshake request.
///
/// Layout (reference `oncp_connect`):
///
/// ```text
/// le16  total body length, excluding this two-byte prefix
/// 00 04 00 00 00                     fixed head
/// le16  hostname length
///       hostname bytes
/// bb 01 00 00 00 00                  fixed tail
/// ```
///
/// The function depends only on `hostname`; the returned bytes are stable.
pub fn hostname_packet(hostname: &str) -> Result<Vec<u8>, OncpError> {
    let body_len = AUTH_PACKET_HEAD.len() + 2 + hostname.len() + AUTH_PACKET_TAIL.len();
    let prefix = u16::try_from(body_len).map_err(|_| OncpError::HostnameTooLong {
        length: hostname.len(),
    })?;

    let mut out = Vec::with_capacity(body_len + RECORD_PREFIX_LEN);
    out.extend_from_slice(&prefix.to_le_bytes());
    out.extend_from_slice(&AUTH_PACKET_HEAD);
    out.extend_from_slice(&(hostname.len() as u16).to_le_bytes());
    out.extend_from_slice(hostname.as_bytes());
    out.extend_from_slice(&AUTH_PACKET_TAIL);
    Ok(out)
}

/// Build the KMP 303 client configuration reply carrying the accepted MTU.
///
/// The payload is one group 6 block with attribute 2 (MTU), exactly as the
/// reference builds it. The record prefix and KMP payload length are
/// little-endian and big-endian respectively.
pub fn client_config_reply(mtu: u16) -> Vec<u8> {
    const GROUP_HEADER_LEN: usize = 6;
    const ATTRIBUTE_HEADER_LEN: usize = 6;
    const MTU_VALUE_LEN: usize = 4;

    let group_len = ATTRIBUTE_HEADER_LEN + MTU_VALUE_LEN;
    let payload_len = GROUP_HEADER_LEN + group_len;
    let record_len = KMP_HEADER_LEN + payload_len;

    let mut out = Vec::with_capacity(RECORD_PREFIX_LEN + record_len);
    out.extend_from_slice(&(record_len as u16).to_le_bytes());
    out.extend_from_slice(&KMP_HEAD);
    out.extend_from_slice(&KMP_CLIENT_CONFIG.to_be_bytes());
    out.extend_from_slice(&KMP_TAIL_OUT);
    out.extend_from_slice(&(payload_len as u16).to_be_bytes());
    out.extend_from_slice(&6u16.to_be_bytes());
    out.extend_from_slice(&(group_len as u32).to_be_bytes());
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&(MTU_VALUE_LEN as u32).to_be_bytes());
    out.extend_from_slice(&u32::from(mtu).to_be_bytes());
    out
}

/// Client-generated ESP inbound keys and SPI sent in a KMP 302.
///
/// The gateway uses the SPI and keys for packets it sends to us, so this is the
/// material our receive SA needs. The 302 wire block is the encryption key,
/// then the HMAC key, then zero padding to [`ESP_KEY_BLOCK_LEN`] bytes.
#[derive(Clone)]
pub struct EspLocalKeys {
    spi: u32,
    encryption: EspEncryption,
    authentication: EspAuthentication,
    encryption_key: SecretKey,
    hmac_key: SecretKey,
}

impl fmt::Debug for EspLocalKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspLocalKeys")
            .field("spi", &format_args!("{:#010x}", self.spi))
            .field("encryption", &self.encryption)
            .field("authentication", &self.authentication)
            .field("encryption_key", &self.encryption_key)
            .field("hmac_key", &self.hmac_key)
            .finish()
    }
}

impl EspLocalKeys {
    /// Validate caller-supplied key material.
    pub fn new(
        spi: u32,
        encryption: EspEncryption,
        authentication: EspAuthentication,
        encryption_key: SecretKey,
        hmac_key: SecretKey,
    ) -> Result<Self, OncpError> {
        if encryption_key.len() != encryption.key_len() {
            return Err(OncpError::KeyLength {
                algorithm: encryption.as_str(),
                expected: encryption.key_len(),
                actual: encryption_key.len(),
            });
        }
        if hmac_key.len() != authentication.key_len() {
            return Err(OncpError::KeyLength {
                algorithm: authentication.as_str(),
                expected: authentication.key_len(),
                actual: hmac_key.len(),
            });
        }
        Ok(Self {
            spi,
            encryption,
            authentication,
            encryption_key,
            hmac_key,
        })
    }

    /// Generate a fresh inbound SPI and keys for the configured transforms.
    ///
    /// See `FallbackRng` for the entropy source and its documented limits.
    pub fn generate(encryption: EspEncryption, authentication: EspAuthentication) -> Self {
        Self::generate_with_iv(encryption, authentication).0
    }

    /// Generate keys and the initial outbound CBC IV from the same entropy
    /// stream, so the IV cannot repeat the key stream when the seeder is
    /// coarse.
    pub fn generate_with_iv(
        encryption: EspEncryption,
        authentication: EspAuthentication,
    ) -> (Self, [u8; 16]) {
        let mut rng = FallbackRng::new();
        let spi = rng.next_u32();
        let mut encryption_key = vec![0u8; encryption.key_len()];
        rng.fill(&mut encryption_key);
        let mut hmac_key = vec![0u8; authentication.key_len()];
        rng.fill(&mut hmac_key);
        let mut initial_iv = [0u8; 16];
        rng.fill(&mut initial_iv);
        (
            Self {
                spi,
                encryption,
                authentication,
                encryption_key: SecretKey::new(encryption_key),
                hmac_key: SecretKey::new(hmac_key),
            },
            initial_iv,
        )
    }

    /// Our inbound SPI (the one the gateway sends to).
    pub const fn spi(&self) -> u32 {
        self.spi
    }

    /// Encryption transform these keys belong to.
    pub const fn encryption(&self) -> EspEncryption {
        self.encryption
    }

    /// Authentication transform these keys belong to.
    pub const fn authentication(&self) -> EspAuthentication {
        self.authentication
    }

    /// Encryption key. Callers must not log or serialise it.
    pub const fn encryption_key(&self) -> &SecretKey {
        &self.encryption_key
    }

    /// HMAC key. Callers must not log or serialise it.
    pub const fn hmac_key(&self) -> &SecretKey {
        &self.hmac_key
    }

    /// The 0x40-byte KMP 302 block: encryption key, HMAC key, zero padding.
    pub fn key_block(&self) -> SecretKey {
        let mut block = vec![0u8; ESP_KEY_BLOCK_LEN];
        block[..self.encryption_key.len()].copy_from_slice(self.encryption_key.expose());
        let hmac_start = self.encryption_key.len();
        block[hmac_start..hmac_start + self.hmac_key.len()].copy_from_slice(self.hmac_key.expose());
        SecretKey::new(block)
    }
}

/// Build the KMP 302 ESP negotiation message.
///
/// Framing matches the KMP 303 builder: a little-endian record length, the
/// 20-byte KMP header with the big-endian message number, the outbound KMP tag,
/// a big-endian payload length, then group 7 attributes 1 (SPI) and 2 (the
/// 0x40-byte key block).
pub fn esp_negotiation(keys: &EspLocalKeys) -> Vec<u8> {
    const GROUP_HEADER_LEN: usize = 6;
    const ATTRIBUTE_HEADER_LEN: usize = 6;
    const SPI_LEN: usize = 4;

    let group_len = ATTRIBUTE_HEADER_LEN + SPI_LEN + ATTRIBUTE_HEADER_LEN + ESP_KEY_BLOCK_LEN;
    let payload_len = GROUP_HEADER_LEN + group_len;
    let record_len = KMP_HEADER_LEN + payload_len;
    let key_block = keys.key_block();

    let mut out = Vec::with_capacity(RECORD_PREFIX_LEN + record_len);
    out.extend_from_slice(&(record_len as u16).to_le_bytes());
    out.extend_from_slice(&KMP_HEAD);
    out.extend_from_slice(&KMP_ESP_NEGOTIATION.to_be_bytes());
    out.extend_from_slice(&KMP_TAIL_OUT);
    out.extend_from_slice(&(payload_len as u16).to_be_bytes());
    out.extend_from_slice(&7u16.to_be_bytes());
    out.extend_from_slice(&(group_len as u32).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(SPI_LEN as u32).to_be_bytes());
    out.extend_from_slice(&keys.spi.to_be_bytes());
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&(ESP_KEY_BLOCK_LEN as u32).to_be_bytes());
    out.extend_from_slice(key_block.expose());
    out
}

/// Generate the initial outbound CBC IV for an ESP session.
///
/// Uses the same documented `FallbackRng` as [`EspLocalKeys::generate`].
pub fn esp_initial_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    FallbackRng::new().fill(&mut iv);
    iv
}

/// Entropy expansion used when no random-number dependency is available.
///
/// # SECURITY NOTE — FALLBACK, NOT A CSPRNG
///
/// This crate does not depend on a random-number crate, and the task forbids
/// adding one. The seed is therefore collected from `SystemTime`, the process
/// id, and fresh [`std::collections::hash_map::RandomState`] instances (which
/// Rust seeds from the operating system). The seed is expanded with
/// HMAC-SHA1. This is a clearly-marked fallback: it is not an audited CSPRNG
/// and should be replaced by the OS random API as soon as the dependency policy
/// permits.
struct FallbackRng {
    key: [u8; 20],
    counter: u64,
}

impl FallbackRng {
    fn new() -> Self {
        const DOMAIN: &[u8] = b"aevan-esp-keygen-fallback-v1";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut seed = Vec::with_capacity(160);
        seed.extend_from_slice(DOMAIN);
        seed.extend_from_slice(&now.as_secs().to_be_bytes());
        seed.extend_from_slice(&now.subsec_nanos().to_be_bytes());
        seed.extend_from_slice(&std::process::id().to_be_bytes());
        for index in 0..8u64 {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            index.hash(&mut hasher);
            now.as_nanos().hash(&mut hasher);
            std::thread::current().id().hash(&mut hasher);
            seed.extend_from_slice(&hasher.finish().to_be_bytes());
        }

        let digest = Sha1::digest(&seed);
        let mut key = [0u8; 20];
        key.copy_from_slice(&digest);
        Self { key, counter: 0 }
    }

    fn fill(&mut self, out: &mut [u8]) {
        const DOMAIN: &[u8] = b"aevan-esp-keygen-fallback-v1";
        for chunk in out.chunks_mut(20) {
            let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&self.key) else {
                // HMAC-SHA1 accepts a key of any length, so this cannot happen;
                // fail closed by leaving the chunk zeroed rather than panicking.
                return;
            };
            mac.update(DOMAIN);
            mac.update(&self.counter.to_be_bytes());
            let digest = mac.finalize().into_bytes();
            chunk.copy_from_slice(&digest[..chunk.len()]);
            self.key.copy_from_slice(&digest);
            self.counter = self.counter.wrapping_add(1);
        }
    }

    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes);
        u32::from_be_bytes(bytes)
    }
}

/// A parsed KMP frame.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KmpFrame<'a> {
    /// KMP message number: 301 config, 302 ESP negotiation, 303 reply.
    pub number: u16,
    /// Payload after the 20-byte KMP header.
    pub payload: &'a [u8],
    /// Declared TLS-record length, excluding the two-byte prefix.
    pub record_length: usize,
}

impl fmt::Debug for KmpFrame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KmpFrame")
            .field("number", &self.number)
            .field("record_length", &self.record_length)
            .field("payload_length", &self.payload.len())
            .finish()
    }
}

impl<'a> KmpFrame<'a> {
    /// Parse an inbound frame (the KMP tag the gateway uses for 301/302).
    pub fn parse(input: &'a [u8]) -> Result<Self, OncpError> {
        Self::parse_with_tail(input, &KMP_TAIL_IN)
    }

    /// Parse an outbound frame (the tag used by the client for 303/302 keys).
    pub fn parse_outbound(input: &'a [u8]) -> Result<Self, OncpError> {
        Self::parse_with_tail(input, &KMP_TAIL_OUT)
    }

    /// Parse a frame in either direction, accepting both KMP tags.
    pub fn parse_any(input: &'a [u8]) -> Result<Self, OncpError> {
        Self::parse_with_tail(input, &KMP_TAIL_IN)
            .or_else(|_| Self::parse_with_tail(input, &KMP_TAIL_OUT))
    }

    fn parse_with_tail(input: &'a [u8], tail: &[u8; 10]) -> Result<Self, OncpError> {
        if input.len() < RECORD_PREFIX_LEN + KMP_HEADER_LEN {
            return Err(OncpError::Truncated {
                needed: RECORD_PREFIX_LEN + KMP_HEADER_LEN,
                available: input.len(),
            });
        }

        let record_length = usize::from(u16::from_le_bytes([input[0], input[1]]));
        let actual = input.len() - RECORD_PREFIX_LEN;
        if record_length != actual {
            return Err(OncpError::RecordLength {
                declared: record_length,
                actual,
            });
        }

        let kmp = &input[RECORD_PREFIX_LEN..];
        if kmp.len() < KMP_HEADER_LEN {
            return Err(OncpError::Truncated {
                needed: KMP_HEADER_LEN,
                available: kmp.len(),
            });
        }
        if kmp[0..6] != KMP_HEAD || kmp[8..18] != tail[..] {
            return Err(OncpError::InvalidKmpHeader);
        }

        let number = u16::from_be_bytes([kmp[6], kmp[7]]);
        let payload_len = usize::from(u16::from_be_bytes([kmp[18], kmp[19]]));
        let available = kmp.len() - KMP_HEADER_LEN;
        if payload_len > available {
            return Err(OncpError::PayloadLength {
                declared: payload_len,
                available,
            });
        }

        Ok(Self {
            number,
            payload: &kmp[KMP_HEADER_LEN..KMP_HEADER_LEN + payload_len],
            record_length,
        })
    }
}

/// A parsed KMP 302 ESP negotiation message.
#[derive(Clone)]
pub struct EspNegotiation {
    /// Outbound ESP SPI, decoded from the big-endian wire field.
    pub outbound_spi: u32,
    /// Encryption transform for the key block.
    pub encryption: EspEncryption,
    /// Authentication transform for the key block.
    pub authentication: EspAuthentication,
    /// Encryption key, split from the 0x40-byte block.
    pub encryption_key: SecretKey,
    /// HMAC key, split from the 0x40-byte block.
    pub hmac_key: SecretKey,
    /// Soft ESP lifetime in bytes from group 8 attr 5, when present.
    pub lifetime_bytes: Option<u32>,
    /// Soft ESP lifetime in seconds from group 8 attr 6, when present.
    pub lifetime_seconds: Option<u32>,
}

impl fmt::Debug for EspNegotiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspNegotiation")
            .field("outbound_spi", &format_args!("{:#010x}", self.outbound_spi))
            .field("encryption", &self.encryption)
            .field("authentication", &self.authentication)
            .field("encryption_key", &self.encryption_key)
            .field("hmac_key", &self.hmac_key)
            .field("lifetime_bytes", &self.lifetime_bytes)
            .field("lifetime_seconds", &self.lifetime_seconds)
            .finish()
    }
}

/// Parse a KMP 302 message and split its 0x40-byte key block.
///
/// The encryption and HMAC key lengths come from the transforms configured for
/// the tunnel (normally decoded from KMP 301 group 8). The block is
/// `encryption_key || hmac_key || unused`, matching the reference. A group 8
/// transform inside the 302 must agree with `encryption`/`authentication`;
/// otherwise this returns [`OncpError::TransformMismatch`] instead of guessing.
pub fn parse_esp_negotiation(
    input: &[u8],
    encryption: EspEncryption,
    authentication: EspAuthentication,
) -> Result<EspNegotiation, OncpError> {
    parse_negotiation(input, encryption, authentication, true)
}

/// Parse a KMP 302 received from the gateway during a live tunnel.
///
/// A gateway-initiated 302 dictates the **client's outbound** SPI and key
/// block. Group 8 transforms are authoritative when present; when absent the
/// caller's current transforms still determine how the 0x40-byte block is
/// split. This is the server-driven rekey path. Unknown attributes inside
/// groups 7 and 8 are ignored and logged by group/attr/length only; any other
/// group is rejected, as in the reference's `parse_conf_pkt`.
pub fn parse_server_rekey(
    input: &[u8],
    encryption: EspEncryption,
    authentication: EspAuthentication,
) -> Result<EspNegotiation, OncpError> {
    parse_negotiation(input, encryption, authentication, false)
}

fn parse_negotiation(
    input: &[u8],
    fallback_encryption: EspEncryption,
    fallback_authentication: EspAuthentication,
    require_transform_match: bool,
) -> Result<EspNegotiation, OncpError> {
    let frame = KmpFrame::parse_any(input)?;
    if frame.number != KMP_ESP_NEGOTIATION {
        return Err(OncpError::UnexpectedMessage {
            expected: KMP_ESP_NEGOTIATION,
            actual: frame.number,
        });
    }

    let mut spi = None;
    let mut key_block = None;
    let mut encryption = fallback_encryption;
    let mut authentication = fallback_authentication;
    let mut encryption_attr = None;
    let mut authentication_attr = None;
    let mut lifetime_bytes = None;
    let mut lifetime_seconds = None;

    for attribute in decode_grouped_attributes(frame.payload)? {
        match (attribute.group, attribute.attr) {
            (7, 1) => {
                if attribute.value.len() != 4 {
                    return Err(OncpError::WrongLength {
                        group: 7,
                        attr: 1,
                        expected: 4,
                        actual: attribute.value.len(),
                    });
                }
                spi = Some(u32::from_be_bytes([
                    attribute.value[0],
                    attribute.value[1],
                    attribute.value[2],
                    attribute.value[3],
                ]));
            }
            (7, 2) => {
                if attribute.value.len() != ESP_KEY_BLOCK_LEN {
                    return Err(OncpError::WrongLength {
                        group: 7,
                        attr: 2,
                        expected: ESP_KEY_BLOCK_LEN,
                        actual: attribute.value.len(),
                    });
                }
                key_block = Some(attribute.value);
            }
            (8, 1) => {
                if attribute.value.len() != 1 {
                    return Err(OncpError::WrongLength {
                        group: 8,
                        attr: 1,
                        expected: 1,
                        actual: attribute.value.len(),
                    });
                }
                let observed = EspEncryption::from_wire(attribute.value[0]).ok_or(
                    OncpError::UnsupportedValue {
                        group: 8,
                        attr: 1,
                        value: attribute.value[0],
                    },
                )?;
                encryption = observed;
                encryption_attr = Some(observed);
            }
            (8, 2) => {
                if attribute.value.len() != 1 {
                    return Err(OncpError::WrongLength {
                        group: 8,
                        attr: 2,
                        expected: 1,
                        actual: attribute.value.len(),
                    });
                }
                let observed = EspAuthentication::from_wire(attribute.value[0]).ok_or(
                    OncpError::UnsupportedValue {
                        group: 8,
                        attr: 2,
                        value: attribute.value[0],
                    },
                )?;
                authentication = observed;
                authentication_attr = Some(observed);
            }
            (8, 5) => {
                if attribute.value.len() != 4 {
                    return Err(OncpError::WrongLength {
                        group: 8,
                        attr: 5,
                        expected: 4,
                        actual: attribute.value.len(),
                    });
                }
                lifetime_bytes = Some(u32::from_be_bytes([
                    attribute.value[0],
                    attribute.value[1],
                    attribute.value[2],
                    attribute.value[3],
                ]));
            }
            (8, 6) => {
                if attribute.value.len() != 4 {
                    return Err(OncpError::WrongLength {
                        group: 8,
                        attr: 6,
                        expected: 4,
                        actual: attribute.value.len(),
                    });
                }
                lifetime_seconds = Some(u32::from_be_bytes([
                    attribute.value[0],
                    attribute.value[1],
                    attribute.value[2],
                    attribute.value[3],
                ]));
            }
            (7, _) | (8, _) => {
                tracing::info!(
                    group = attribute.group,
                    attr = attribute.attr,
                    length = attribute.value.len(),
                    "ignoring an unknown KMP 302 attribute"
                );
            }
            (group, attr) => return Err(OncpError::NonEspTlv { group, attr }),
        }
    }

    if require_transform_match {
        if let Some(observed) = encryption_attr {
            if observed != fallback_encryption {
                return Err(OncpError::TransformMismatch { group: 8, attr: 1 });
            }
        }
        if let Some(observed) = authentication_attr {
            if observed != fallback_authentication {
                return Err(OncpError::TransformMismatch { group: 8, attr: 2 });
            }
        }
    }

    let outbound_spi = spi.ok_or(OncpError::MissingEspSpi)?;
    let key_block = key_block.ok_or(OncpError::MissingEspKeyBlock)?;
    let enc_len = encryption.key_len();
    let hmac_len = authentication.key_len();
    let needed = enc_len + hmac_len;
    if key_block.len() < needed {
        return Err(OncpError::KeyBlockTooShort {
            needed,
            actual: key_block.len(),
        });
    }

    Ok(EspNegotiation {
        outbound_spi,
        encryption,
        authentication,
        encryption_key: SecretKey::new(key_block[..enc_len].to_vec()),
        hmac_key: SecretKey::new(key_block[enc_len..needed].to_vec()),
        lifetime_bytes,
        lifetime_seconds,
    })
}

/// User-Agent sent with the live oNCP handshake request.
pub const HANDSHAKE_USER_AGENT: &str = concat!("aevan/", env!("CARGO_PKG_VERSION"));

/// The byte stream the handshake driver needs.
///
/// [`RawTls`] implements it for a real session. Tests provide an in-memory
/// stream so the framing can be exercised without a socket.
pub trait HandshakeIo {
    /// Write every byte.
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()>;
    /// Read exactly `buffer.len()` bytes.
    fn read_exact(&mut self, buffer: &mut [u8]) -> io::Result<()>;
    /// Read up to `buffer.len()` bytes, returning the count.
    fn read_some(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
}

impl HandshakeIo for RawTls {
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        RawTls::write_all(self, bytes)
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        RawTls::read_exact(self, buffer)
    }

    fn read_some(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        RawTls::read_some(self, buffer)
    }
}

/// Which `Content-Length` convention produced a handshake result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentLengthVariant {
    /// `Content-Length` equal to the hostname packet's real length.
    Actual,
    /// The reference's fixed `Content-Length: 256`; the packet itself is sent
    /// unpadded, after the HTTP 200, exactly as the reference does.
    Fixed256,
}

impl ContentLengthVariant {
    /// Stable display name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Actual => "actual",
            Self::Fixed256 => "fixed256",
        }
    }
}

/// An owned KMP message parsed from the handshake response.
#[derive(Clone, PartialEq, Eq)]
pub struct KmpMessageOwned {
    /// KMP message number (301 configuration, 302 ESP negotiation, 303 reply).
    pub number: u16,
    /// Declared TLS-record length, excluding the two-byte prefix.
    pub record_length: usize,
    /// KMP payload, with the 20-byte KMP header removed.
    pub payload: Vec<u8>,
}

impl fmt::Debug for KmpMessageOwned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KmpMessageOwned")
            .field("number", &self.number)
            .field("record_length", &self.record_length)
            .field("payload_length", &self.payload.len())
            .finish()
    }
}

/// One raw record read from the gateway's binary response.
#[derive(Clone, PartialEq, Eq)]
pub struct HandshakeFrame {
    /// Declared record length, excluding the two-byte prefix.
    pub declared_length: usize,
    /// Record body, exactly as it followed the length prefix.
    pub body: Vec<u8>,
    /// Offset of `body` inside the attempt's `response_bytes`.
    pub body_offset: usize,
    /// KMP message number when this chunk starts with a KMP header.
    pub message_number: Option<u16>,
}

impl fmt::Debug for HandshakeFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeFrame")
            .field("declared_length", &self.declared_length)
            .field("body_length", &self.body.len())
            .field("body_offset", &self.body_offset)
            .field("message_number", &self.message_number)
            .finish()
    }
}

/// One attempt at the post-login binary handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct HandshakeAttempt {
    /// Which `Content-Length` convention this attempt used.
    pub variant: ContentLengthVariant,
    /// HTTP status of the oNCP request, when one was received.
    pub http_status: Option<u16>,
    /// HTTP reason phrase of the oNCP request, when one was received.
    pub http_reason: Option<String>,
    /// HTTP response headers, in wire order. May contain `Set-Cookie`.
    pub http_headers: Vec<(String, String)>,
    /// The gateway's three-byte response status byte, when one was received.
    pub status: Option<u8>,
    /// Every raw binary record read after the status.
    pub frames: Vec<HandshakeFrame>,
    /// The parsed KMP message, when framing succeeded.
    pub message: Option<KmpMessageOwned>,
    /// The exact HTTP request bytes written for this attempt (contains cookies).
    pub request_bytes: Vec<u8>,
    /// Every raw response byte read for this attempt, including a partial
    /// HTTP response or binary record.
    pub response_bytes: Vec<u8>,
    /// Offset in `response_bytes` at which a transport read failed, if it did.
    pub read_offset: Option<usize>,
    /// Whether this attempt ended on a transport read or write error.
    pub transport_error: bool,
    /// Why this attempt did not produce a usable KMP 301, if it did not.
    pub failure: Option<String>,
}

impl fmt::Debug for HandshakeAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeAttempt")
            .field("variant", &self.variant)
            .field("http_status", &self.http_status)
            .field("http_reason", &self.http_reason)
            .field("status", &self.status)
            .field("frames", &self.frames.len())
            .field("message", &self.message)
            .field("request_bytes", &self.request_bytes.len())
            .field("response_bytes", &self.response_bytes.len())
            .field("read_offset", &self.read_offset)
            .field("transport_error", &self.transport_error)
            .field("failure", &self.failure)
            .finish()
    }
}

impl HandshakeAttempt {
    /// Whether this attempt produced HTTP 200, status 0 and a KMP 301.
    pub fn succeeded(&self) -> bool {
        self.failure.is_none()
            && self.http_status == Some(200)
            && self.status == Some(0)
            && self
                .message
                .as_ref()
                .is_some_and(|message| message.number == KMP_CONFIG)
    }
}

/// The complete result of the live handshake, including failed attempts.
#[derive(Clone, PartialEq, Eq)]
pub struct HandshakeOutcome {
    /// Attempts in order: the fixed 256 length first, then the single
    /// actual-length fallback.
    pub attempts: Vec<HandshakeAttempt>,
    /// The variant that produced the KMP 301, or `None` if both failed.
    pub working_variant: Option<ContentLengthVariant>,
    /// The parsed KMP 301 from the working attempt.
    pub message: Option<KmpMessageOwned>,
}

impl fmt::Debug for HandshakeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeOutcome")
            .field("attempts", &self.attempts.len())
            .field("working_variant", &self.working_variant)
            .field("message", &self.message)
            .finish()
    }
}

impl HandshakeOutcome {
    /// Whether the handshake produced a KMP 301.
    pub fn succeeded(&self) -> bool {
        self.message
            .as_ref()
            .is_some_and(|message| message.number == KMP_CONFIG)
    }

    /// Whether the actual-length fallback was tried.
    pub fn fallback_used(&self) -> bool {
        self.attempts.len() > 1
    }

    /// The last attempt, which carries the bytes to show on failure.
    pub fn last_attempt(&self) -> Option<&HandshakeAttempt> {
        self.attempts.last()
    }

    /// Whether the final attempt failed at the transport layer.
    pub fn transport_failed(&self) -> bool {
        self.last_attempt()
            .is_some_and(|attempt| attempt.transport_error)
    }
}

/// Connection or framing failure that prevents the driver from returning an
/// observation. Gateway responses are returned as a [`HandshakeOutcome`] with
/// `message: None` so the caller can still dump what arrived.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// Network or TLS failure.
    #[error("oNCP handshake transport: {0}")]
    Transport(#[from] ProtoError),
    /// Local I/O on the handshake stream.
    #[error("oNCP handshake I/O: {0}")]
    Io(#[from] io::Error),
    /// A local framing constant could not be built.
    #[error("oNCP handshake framing: {0}")]
    Framing(#[from] OncpError),
}

struct HttpHandshakeResponse {
    status_code: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

struct BinaryResponse {
    status: u8,
    frames: Vec<HandshakeFrame>,
    response_bytes: Vec<u8>,
    message: Option<KmpMessageOwned>,
    failure: Option<String>,
}

/// Connect a fresh TLS session and run the live oNCP handshake.
///
/// The session is the same TLS configuration as the HTTP client. `cookie_header`
/// is the caller's complete `Cookie:` value; it is never logged or rendered.
pub fn handshake_live(
    url: &Url,
    timeout: Duration,
    hostname: &str,
    cookie_header: Option<&str>,
) -> Result<HandshakeOutcome, HandshakeError> {
    let mut io = RawTls::connect(url, timeout).map_err(HandshakeError::Transport)?;
    handshake(&mut io, &url.host_header(), hostname, cookie_header)
}

/// Run exactly one oNCP handshake attempt with the reference fixed 256 length.
///
/// This is the `aevan connect` handshake: it has no Content-Length fallback and
/// no retry, so a gateway status byte is reported immediately.
pub fn handshake_once<S: HandshakeIo>(
    io: &mut S,
    host_header: &str,
    hostname: &str,
    cookie_header: Option<&str>,
) -> Result<HandshakeAttempt, HandshakeError> {
    attempt(
        io,
        host_header,
        hostname,
        cookie_header,
        ContentLengthVariant::Fixed256,
    )
}

/// Connect a fresh TLS session and run exactly one oNCP attempt.
///
/// The TCP/TLS connect is retried once. That is a *connection* retry, not an
/// authentication attempt: the gateway intermittently drops or blackholes a
/// fresh connection when several have just been opened from the same client, and
/// the failure surfaces as `WSAETIMEDOUT` before any byte is exchanged. No HTTP
/// request is sent twice, and no credential is involved.
pub fn handshake_live_once(
    url: &Url,
    timeout: Duration,
    hostname: &str,
    cookie_header: Option<&str>,
) -> Result<HandshakeAttempt, HandshakeError> {
    const CONNECT_ATTEMPTS: usize = 3;
    let mut last_error = None;

    for attempt in 0..CONNECT_ATTEMPTS {
        match RawTls::connect(url, timeout) {
            Ok(mut io) => {
                return handshake_once(&mut io, &url.host_header(), hostname, cookie_header);
            }
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < CONNECT_ATTEMPTS {
                    std::thread::sleep(Duration::from_millis(1500));
                }
            }
        }
    }

    Err(HandshakeError::Transport(
        last_error.expect("at least one connect attempt ran"),
    ))
}

/// A completed oNCP handshake whose TLS stream is still open.
///
/// `aevan connect` keeps this value alive while ESP runs: the KMP 302 and 303
/// messages go back over the same TLS stream, and closing the stream tells the
/// gateway the NC session ended. The peer address is the TLS peer, which is the
/// ESP UDP endpoint; the KMP 301 `gateway` field is an internal tunnel address,
/// not the public host to send ESP to.
pub struct LiveHandshake {
    io: RawTls,
    attempt: HandshakeAttempt,
    peer_addr: SocketAddr,
}

impl fmt::Debug for LiveHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveHandshake")
            .field("attempt", &self.attempt)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

impl LiveHandshake {
    /// The single handshake attempt, including its KMP 301 message.
    pub const fn attempt(&self) -> &HandshakeAttempt {
        &self.attempt
    }

    /// The TLS peer address, used as the ESP UDP endpoint.
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Write bytes on the still-open oNCP TLS stream.
    pub fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.io.write_all(bytes)
    }

    /// Change the TLS stream read timeout.
    pub fn set_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.io.set_read_timeout(timeout)
    }

    /// Poll the retained oNCP stream for one pending KMP message.
    ///
    /// The socket read timeout is briefly shortened so the ESP loop does not
    /// block. `Ok(None)` means nothing arrived; a partial record is an error.
    pub fn recv_kmp(&mut self) -> io::Result<Option<crate::esp::ReceivedKmp>> {
        const POLL_TIMEOUT: Duration = Duration::from_millis(10);
        const RECORD_TIMEOUT: Duration = Duration::from_millis(200);

        self.io.set_read_timeout(POLL_TIMEOUT)?;
        let mut prefix = [0u8; 2];
        let mut filled = 0;
        while filled < prefix.len() {
            match self.io.read_some(&mut prefix[filled..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the gateway closed the retained KMP stream",
                    ))
                }
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if is_timeout(&error) && filled == 0 => return Ok(None),
                Err(error) => return Err(error),
            }
        }

        let record_length = usize::from(u16::from_le_bytes(prefix));
        let mut body = vec![0u8; record_length];
        self.io.set_read_timeout(RECORD_TIMEOUT)?;
        self.io.read_exact(&mut body)?;

        let mut record = Vec::with_capacity(RECORD_PREFIX_LEN + body.len());
        record.extend_from_slice(&prefix);
        record.extend_from_slice(&body);

        Ok(Some(crate::esp::ReceivedKmp {
            number: kmp_message_number(&body).unwrap_or(0),
            record_length,
            payload_len: body.len().saturating_sub(KMP_HEADER_LEN),
            record,
        }))
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// A rekey writes its KMP 302/303 on the same TLS stream that carried KMP 301
/// and polls that stream for the confirming KMP 303 reply.
impl crate::esp::KmpChannel for LiveHandshake {
    fn send_kmp(&mut self, message: &[u8]) -> io::Result<()> {
        self.write_all(message)
    }

    fn recv_kmp(&mut self) -> io::Result<Option<crate::esp::ReceivedKmp>> {
        LiveHandshake::recv_kmp(self)
    }
}

/// Connect once and run exactly one oNCP handshake, keeping the stream open.
///
/// Unlike [`handshake_live_once`], this does not retry the TCP/TLS connect.
/// `aevan connect` uses it so the KMP 302/303 replies can be written on the same
/// stream that received KMP 301.
pub fn handshake_live_session(
    url: &Url,
    timeout: Duration,
    hostname: &str,
    cookie_header: Option<&str>,
) -> Result<LiveHandshake, HandshakeError> {
    let mut io = RawTls::connect(url, timeout).map_err(HandshakeError::Transport)?;
    let peer_addr = io.peer_addr().map_err(HandshakeError::Io)?;
    let attempt = handshake_once(&mut io, &url.host_header(), hostname, cookie_header)?;
    Ok(LiveHandshake {
        io,
        attempt,
        peer_addr,
    })
}

/// Run the live oNCP handshake over an already connected byte stream.
///
/// The first attempt uses the reference implementation's literal `Content-Length: 256`
/// with a zero-padded hostname packet. That is the reference convention, and
/// the real-length variant makes the gateway answer with status byte 1. If the
/// fixed-256 attempt does not yield an HTTP 200 plus KMP 301, exactly one
/// fallback repeats the request with the hostname packet's actual length.
/// There is no loop. The session already exists, so neither attempt
/// authenticates again.
pub fn handshake<S: HandshakeIo>(
    io: &mut S,
    host_header: &str,
    hostname: &str,
    cookie_header: Option<&str>,
) -> Result<HandshakeOutcome, HandshakeError> {
    let first = attempt(
        io,
        host_header,
        hostname,
        cookie_header,
        ContentLengthVariant::Fixed256,
    )?;
    if first.succeeded() {
        let message = first.message.clone();
        return Ok(HandshakeOutcome {
            attempts: vec![first],
            working_variant: Some(ContentLengthVariant::Fixed256),
            message,
        });
    }

    let second = attempt(
        io,
        host_header,
        hostname,
        cookie_header,
        ContentLengthVariant::Actual,
    )?;
    let working_variant = second.succeeded().then_some(ContentLengthVariant::Actual);
    let message = second.message.clone();
    Ok(HandshakeOutcome {
        attempts: vec![first, second],
        working_variant,
        message,
    })
}

fn attempt<S: HandshakeIo>(
    io: &mut S,
    host_header: &str,
    hostname: &str,
    cookie_header: Option<&str>,
    variant: ContentLengthVariant,
) -> Result<HandshakeAttempt, HandshakeError> {
    let auth_packet = hostname_packet(hostname)?;
    let (content_length, auth_packet) = match variant {
        ContentLengthVariant::Actual => (auth_packet.len(), auth_packet),
        ContentLengthVariant::Fixed256 => {
            if auth_packet.len() > HANDSHAKE_CONTENT_LENGTH {
                return Ok(HandshakeAttempt {
                    variant,
                    http_status: None,
                    http_reason: None,
                    http_headers: Vec::new(),
                    status: None,
                    frames: Vec::new(),
                    message: None,
                    request_bytes: Vec::new(),
                    response_bytes: Vec::new(),
                    read_offset: None,
                    transport_error: false,
                    failure: Some(format!(
                        "hostname packet is {} bytes, longer than the fixed 256-byte fallback",
                        auth_packet.len()
                    )),
                });
            }
            // The reference declares `Content-Length: 256` and then sends only
            // the hostname packet (15 + len bytes) after the HTTP 200. It never
            // pads the packet, so neither do we: a padded tail would arrive as
            // junk after the packet.
            (HANDSHAKE_CONTENT_LENGTH, auth_packet)
        }
    };

    let request = handshake_request_with_content_length(
        host_header,
        HANDSHAKE_USER_AGENT,
        cookie_header,
        content_length,
    )?;

    let mut response_bytes = Vec::new();

    if let Err(error) = io.write_all(&request) {
        return Ok(HandshakeAttempt {
            variant,
            http_status: None,
            http_reason: None,
            http_headers: Vec::new(),
            status: None,
            frames: Vec::new(),
            message: None,
            request_bytes: request,
            response_bytes,
            read_offset: None,
            transport_error: true,
            failure: Some(format!("transport write: {error}")),
        });
    }

    let http = match read_http_response(io, &mut response_bytes) {
        Ok(response) => response,
        Err(error) => {
            let read_offset = response_bytes.len();
            return Ok(HandshakeAttempt {
                variant,
                http_status: None,
                http_reason: None,
                http_headers: Vec::new(),
                status: None,
                frames: Vec::new(),
                message: None,
                request_bytes: request,
                response_bytes,
                read_offset: Some(read_offset),
                transport_error: true,
                failure: Some(format!("transport read: {error}")),
            });
        }
    };

    if http.status_code != 200 {
        return Ok(HandshakeAttempt {
            variant,
            http_status: Some(http.status_code),
            http_reason: Some(http.reason.clone()),
            http_headers: http.headers,
            status: None,
            frames: Vec::new(),
            message: None,
            request_bytes: request,
            response_bytes,
            read_offset: None,
            transport_error: false,
            failure: Some(format!("unexpected HTTP status {}", http.status_code)),
        });
    }

    if let Err(error) = io.write_all(&auth_packet) {
        return Ok(HandshakeAttempt {
            variant,
            http_status: Some(http.status_code),
            http_reason: Some(http.reason.clone()),
            http_headers: http.headers,
            status: None,
            frames: Vec::new(),
            message: None,
            request_bytes: request,
            response_bytes,
            read_offset: None,
            transport_error: true,
            failure: Some(format!("transport write: {error}")),
        });
    }

    let binary = match read_binary_response(io, &mut response_bytes) {
        Ok(binary) => binary,
        Err(error) => {
            let read_offset = response_bytes.len();
            return Ok(HandshakeAttempt {
                variant,
                http_status: Some(http.status_code),
                http_reason: Some(http.reason.clone()),
                http_headers: http.headers,
                status: None,
                frames: Vec::new(),
                message: None,
                request_bytes: request,
                response_bytes,
                read_offset: Some(read_offset),
                transport_error: true,
                failure: Some(format!("transport read: {error}")),
            });
        }
    };

    let failure = if binary.status != 0 {
        Some(format!("gateway status byte 0x{:02x}", binary.status))
    } else {
        binary.failure
    };

    Ok(HandshakeAttempt {
        variant,
        http_status: Some(http.status_code),
        http_reason: Some(http.reason.clone()),
        http_headers: http.headers,
        status: Some(binary.status),
        frames: binary.frames,
        message: binary.message,
        request_bytes: request,
        response_bytes: binary.response_bytes,
        read_offset: None,
        transport_error: false,
        failure,
    })
}

fn read_http_response<S: HandshakeIo>(
    io: &mut S,
    response_bytes: &mut Vec<u8>,
) -> io::Result<HttpHandshakeResponse> {
    const MAX_HEADER_BYTES: usize = 64 * 1024;

    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        read_exact_logged(io, &mut byte, response_bytes)?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        if header.len() > MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP response headers are too large"));
        }
    }

    let text = std::str::from_utf8(&header)
        .map_err(|_| invalid_data("HTTP response headers are not valid UTF-8"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP status line"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(invalid_data(
            "response does not start with an HTTP status line",
        ));
    }
    let status_code = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| invalid_data("invalid HTTP status line"))?;
    let reason = parts.next().unwrap_or_default().to_owned();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid_data("malformed HTTP response header"))?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let mut content_length = None;
    let mut chunked = false;
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<usize>().ok();
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    if chunked {
        drain_chunked_body(io, response_bytes)?;
    } else if let Some(mut remaining) = content_length {
        let mut buffer = [0u8; 4096];
        while remaining > 0 {
            let take = remaining.min(buffer.len());
            read_exact_logged(io, &mut buffer[..take], response_bytes)?;
            remaining -= take;
        }
    }

    Ok(HttpHandshakeResponse {
        status_code,
        reason,
        headers,
    })
}

fn drain_chunked_body<S: HandshakeIo>(io: &mut S, response_bytes: &mut Vec<u8>) -> io::Result<()> {
    let mut byte = [0u8; 1];
    loop {
        let mut size_line = Vec::new();
        loop {
            read_exact_logged(io, &mut byte, response_bytes)?;
            size_line.push(byte[0]);
            if size_line.ends_with(b"\r\n") {
                break;
            }
            if size_line.len() > 64 {
                return Err(invalid_data("chunk size line is too long"));
            }
        }
        let size_text = std::str::from_utf8(&size_line[..size_line.len() - 2])
            .map_err(|_| invalid_data("chunk size is not ASCII"))?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| invalid_data("invalid chunk size"))?;
        if size == 0 {
            // Consume optional trailers up to the terminating blank line.
            loop {
                let mut trailer = Vec::new();
                loop {
                    read_exact_logged(io, &mut byte, response_bytes)?;
                    trailer.push(byte[0]);
                    if trailer.ends_with(b"\r\n") {
                        break;
                    }
                }
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
        }
        let mut remaining = size;
        let mut buffer = [0u8; 4096];
        while remaining > 0 {
            let take = remaining.min(buffer.len());
            read_exact_logged(io, &mut buffer[..take], response_bytes)?;
            remaining -= take;
        }
        let mut terminator = [0u8; 2];
        read_exact_logged(io, &mut terminator, response_bytes)?;
        if terminator != *b"\r\n" {
            return Err(invalid_data("missing chunk terminator"));
        }
    }
}

fn read_binary_response<S: HandshakeIo>(
    io: &mut S,
    response_bytes: &mut Vec<u8>,
) -> io::Result<BinaryResponse> {
    let mut frames = Vec::new();

    let mut status_field = [0u8; 3];
    read_exact_logged(io, &mut status_field, response_bytes)?;
    let declared = usize::from(u16::from_le_bytes([status_field[0], status_field[1]]));
    let status = status_field[2];

    if declared < 1 {
        return Ok(BinaryResponse {
            status,
            frames,
            response_bytes: std::mem::take(response_bytes),
            message: None,
            failure: Some("gateway sent a zero-length record".into()),
        });
    }
    if status != 0 {
        // Drain the rest of a concatenated record so a same-session fallback
        // starts at a record boundary rather than in the middle of this one.
        if declared > 1 {
            let mut body = vec![0u8; declared - 1];
            read_exact_logged(io, &mut body, response_bytes)?;
        }
        return Ok(BinaryResponse {
            status,
            frames,
            response_bytes: std::mem::take(response_bytes),
            message: None,
            failure: Some(format!("gateway status byte 0x{status:02x}")),
        });
    }

    let mut kmp_body = Vec::new();

    if declared == 1 {
        // The status was its own record; the next bytes are a new record.
        let frame = read_record(io, response_bytes)?;
        if !is_legacy_ip_frame(&frame.body) {
            kmp_body.extend_from_slice(&frame.body);
        }
        frames.push(frame);
    } else {
        // KMP bytes were concatenated after the status in the same record.
        let body_len = declared - 1;
        let body_offset = response_bytes.len();
        let mut body = vec![0u8; body_len];
        read_exact_logged(io, &mut body, response_bytes)?;
        let message_number = kmp_message_number(&body);
        if !is_legacy_ip_frame(&body) {
            kmp_body.extend_from_slice(&body);
        }
        frames.push(HandshakeFrame {
            declared_length: body_len,
            body,
            body_offset,
            message_number,
        });
    }

    let mut guard = 0;
    while kmp_body.len() < KMP_HEADER_LEN {
        guard += 1;
        if guard > 1024 {
            return Ok(BinaryResponse {
                status,
                frames,
                response_bytes: std::mem::take(response_bytes),
                message: None,
                failure: Some("gateway sent too many empty records".into()),
            });
        }
        let frame = read_record(io, response_bytes)?;
        if !is_legacy_ip_frame(&frame.body) {
            kmp_body.extend_from_slice(&frame.body);
        }
        frames.push(frame);
    }

    let number = u16::from_be_bytes([kmp_body[6], kmp_body[7]]);
    let payload_len = usize::from(u16::from_be_bytes([kmp_body[18], kmp_body[19]]));
    let expected = KMP_HEADER_LEN + payload_len;

    let mut guard = 0;
    while kmp_body.len() < expected {
        guard += 1;
        if guard > 1024 {
            return Ok(BinaryResponse {
                status,
                frames,
                response_bytes: std::mem::take(response_bytes),
                message: None,
                failure: Some("gateway sent too many continuation records".into()),
            });
        }
        let frame = read_record(io, response_bytes)?;
        if !is_legacy_ip_frame(&frame.body) {
            kmp_body.extend_from_slice(&frame.body);
        }
        frames.push(frame);
    }

    if kmp_body.len() < expected {
        return Ok(BinaryResponse {
            status,
            frames,
            response_bytes: std::mem::take(response_bytes),
            message: None,
            failure: Some(format!(
                "truncated KMP message: need {expected} bytes, have {}",
                kmp_body.len()
            )),
        });
    }

    let message_body = &kmp_body[..expected];
    let parsed = KmpFrame::parse_any(&framed_record(message_body))
        .ok()
        .map(|frame| KmpMessageOwned {
            number: frame.number,
            record_length: frame.record_length,
            payload: frame.payload.to_vec(),
        });
    let message = parsed
        .as_ref()
        .filter(|message| message.number == KMP_CONFIG)
        .cloned();
    let failure = if message.is_some() {
        None
    } else {
        Some(format!("expected KMP message {KMP_CONFIG}, got {number}"))
    };

    Ok(BinaryResponse {
        status,
        frames,
        response_bytes: std::mem::take(response_bytes),
        message,
        failure,
    })
}

fn read_exact_logged<S: HandshakeIo>(
    io: &mut S,
    buffer: &mut [u8],
    response_bytes: &mut Vec<u8>,
) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        match io.read_some(&mut buffer[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the peer closed the stream before the record was complete",
                ))
            }
            Ok(count) => {
                response_bytes.extend_from_slice(&buffer[filled..filled + count]);
                filled += count;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_record<S: HandshakeIo>(
    io: &mut S,
    response_bytes: &mut Vec<u8>,
) -> io::Result<HandshakeFrame> {
    let mut prefix = [0u8; 2];
    read_exact_logged(io, &mut prefix, response_bytes)?;
    let declared_length = usize::from(u16::from_le_bytes(prefix));
    let body_offset = response_bytes.len();
    let mut body = vec![0u8; declared_length];
    read_exact_logged(io, &mut body, response_bytes)?;
    let message_number = kmp_message_number(&body);
    Ok(HandshakeFrame {
        declared_length,
        body,
        body_offset,
        message_number,
    })
}

fn framed_record(body: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(2 + body.len());
    framed.extend_from_slice(&(body.len() as u16).to_le_bytes());
    framed.extend_from_slice(body);
    framed
}

fn kmp_message_number(body: &[u8]) -> Option<u16> {
    if body.len() < KMP_HEADER_LEN || body[0..6] != KMP_HEAD {
        return None;
    }
    let tail = &body[8..18];
    if tail != KMP_TAIL_IN && tail != KMP_TAIL_OUT {
        return None;
    }
    Some(u16::from_be_bytes([body[6], body[7]]))
}

fn is_legacy_ip_frame(body: &[u8]) -> bool {
    body.len() >= 21
        && body[0..6] == KMP_HEAD
        && body[8] == 0
        && body[9..18] == KMP_TAIL_IN[1..]
        && u16::from_be_bytes([body[6], body[7]]) == 300
        && usize::from(u16::from_be_bytes([body[18], body[19]])) + KMP_HEADER_LEN == body.len()
        && body[20] == 0x45
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn check_header_value(value: &str) -> Result<(), OncpError> {
    if value.contains('\r') || value.contains('\n') {
        return Err(OncpError::InvalidHeader("CR or LF in header value".into()));
    }
    Ok(())
}

/// Errors from the oNCP handshake framing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OncpError {
    /// The buffer ended before a complete record or header.
    #[error("truncated oNCP frame: need {needed} bytes, {available} available")]
    Truncated {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// The little-endian record prefix did not match the buffer.
    #[error("oNCP record length {declared} does not match body length {actual}")]
    RecordLength {
        /// Declared record length, excluding the prefix.
        declared: usize,
        /// Observed body length.
        actual: usize,
    },
    /// The KMP header constants were not present.
    #[error("oNCP KMP header is not the expected tag")]
    InvalidKmpHeader,
    /// The KMP payload length exceeded the record.
    #[error("oNCP KMP payload length {declared} exceeds available {available}")]
    PayloadLength {
        /// Declared payload length.
        declared: usize,
        /// Payload bytes available.
        available: usize,
    },
    /// A frame carried a message number the caller did not expect.
    #[error("expected KMP message {expected}, got {actual}")]
    UnexpectedMessage {
        /// Expected message number.
        expected: u16,
        /// Observed message number.
        actual: u16,
    },
    /// A known attribute had the wrong length.
    #[error("oNCP attribute {group}/{attr} has length {actual}, expected {expected}")]
    WrongLength {
        /// Attribute group.
        group: u16,
        /// Attribute number.
        attr: u16,
        /// Expected length.
        expected: usize,
        /// Observed length.
        actual: usize,
    },
    /// A transform attribute carried a value this build cannot map.
    #[error("oNCP attribute {group}/{attr} has unsupported value {value}")]
    UnsupportedValue {
        /// Attribute group.
        group: u16,
        /// Attribute number.
        attr: u16,
        /// Observed value.
        value: u8,
    },
    /// A 302 transform disagreed with the configured tunnel transforms.
    #[error("oNCP KMP 302 transform {group}/{attr} disagrees with the configured tunnel")]
    TransformMismatch {
        /// Attribute group.
        group: u16,
        /// Attribute number.
        attr: u16,
    },
    /// A 302 contained a non-ESP TLV group.
    #[error("oNCP KMP 302 contains non-ESP TLV {group}/{attr}")]
    NonEspTlv {
        /// Attribute group.
        group: u16,
        /// Attribute number.
        attr: u16,
    },
    /// A 302 did not carry an outbound SPI.
    #[error("oNCP KMP 302 did not carry an outbound SPI (group 7 attr 1)")]
    MissingEspSpi,
    /// A 302 did not carry the key block.
    #[error("oNCP KMP 302 did not carry the ESP key block (group 7 attr 2)")]
    MissingEspKeyBlock,
    /// The key block was shorter than the configured key lengths.
    #[error("oNCP ESP key block is {actual} bytes, need {needed}")]
    KeyBlockTooShort {
        /// Bytes required by the transforms.
        needed: usize,
        /// Bytes observed.
        actual: usize,
    },
    /// A key had the wrong length for its transform.
    #[error("{algorithm} key is {actual} bytes, expected {expected}")]
    KeyLength {
        /// Transform name.
        algorithm: &'static str,
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// A TLV payload could not be decoded.
    #[error("oNCP TLV payload: {0}")]
    Ncp(#[from] NcpError),
    /// The hostname was too long for the little-endian length field.
    #[error("hostname of {length} bytes does not fit the oNCP length field")]
    HostnameTooLong {
        /// Hostname length in bytes.
        length: usize,
    },
    /// A header value could split the HTTP request.
    #[error("invalid oNCP handshake header: {0}")]
    InvalidHeader(String),
}

// Keep the message constants available from this module and lib.rs without
// duplicating their values.
const _: () = {
    assert!(KMP_CONFIG == 301);
    assert!(KMP_ESP_NEGOTIATION == 302);
    assert!(KMP_CLIENT_CONFIG == 303);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ncp::{decode_attributes, NcpConfig};
    use std::collections::VecDeque;

    const SYNTHETIC_KMP_301: &[u8] = include_bytes!("../tests/fixtures/ncp-config-kmp.bin");
    const HTTP_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    struct ScriptedIo {
        input: VecDeque<u8>,
        written: Vec<u8>,
    }

    impl ScriptedIo {
        fn new(bytes: &[u8]) -> Self {
            Self {
                input: bytes.iter().copied().collect(),
                written: Vec::new(),
            }
        }
    }

    impl HandshakeIo for ScriptedIo {
        fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.written.extend_from_slice(bytes);
            Ok(())
        }

        fn read_exact(&mut self, buffer: &mut [u8]) -> io::Result<()> {
            for slot in buffer {
                *slot = self.input.pop_front().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "scripted stream ended")
                })?;
            }
            Ok(())
        }

        fn read_some(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = buffer.len().min(self.input.len());
            for slot in &mut buffer[..count] {
                *slot = self.input.pop_front().expect("count bounded by length");
            }
            Ok(count)
        }
    }

    fn decoded_config(outcome: &HandshakeOutcome) -> NcpConfig {
        let message = outcome.message.as_ref().expect("KMP 301");
        assert_eq!(message.number, KMP_CONFIG);
        let attributes = decode_attributes(&message.payload).expect("attributes");
        NcpConfig::from_attributes(attributes).expect("config")
    }

    #[test]
    fn reads_a_status_and_kmp_301_in_one_concatenated_record() {
        let kmp_body = &SYNTHETIC_KMP_301[2..];
        let mut script = Vec::new();
        script.extend_from_slice(HTTP_OK);
        // One record: length includes the status byte, then status 0, then KMP.
        script.extend_from_slice(&((kmp_body.len() + 1) as u16).to_le_bytes());
        script.push(0);
        script.extend_from_slice(kmp_body);

        let mut io = ScriptedIo::new(&script);
        let outcome = handshake(&mut io, "vpn.example.net", "aevan-host", None).expect("handshake");

        assert!(outcome.succeeded());
        assert_eq!(
            outcome.working_variant,
            Some(ContentLengthVariant::Fixed256)
        );
        assert!(!outcome.fallback_used());
        assert_eq!(outcome.last_attempt().expect("attempt").status, Some(0));
        assert_eq!(outcome.last_attempt().expect("attempt").frames.len(), 1);
        assert_eq!(decoded_config(&outcome).mtu, Some(1396));
        assert!(io
            .written
            .windows(b"Content-Length: ".len())
            .any(|window| window == b"Content-Length: "));
    }

    #[test]
    fn reads_a_status_record_followed_by_a_separate_kmp_record() {
        let mut script = Vec::new();
        script.extend_from_slice(HTTP_OK);
        // Status as its own record: length 1, status 0.
        script.extend_from_slice(&[0x01, 0x00, 0x00]);
        // A separate record with its own little-endian prefix.
        script.extend_from_slice(SYNTHETIC_KMP_301);

        let mut io = ScriptedIo::new(&script);
        let outcome = handshake(&mut io, "vpn.example.net", "aevan-host", None).expect("handshake");

        assert!(outcome.succeeded());
        assert_eq!(
            outcome.working_variant,
            Some(ContentLengthVariant::Fixed256)
        );
        assert_eq!(outcome.last_attempt().expect("attempt").frames.len(), 1);
        assert_eq!(decoded_config(&outcome).mtu, Some(1396));
    }

    #[test]
    fn uses_exactly_one_actual_length_fallback_after_a_gateway_error() {
        let mut script = Vec::new();
        // First attempt (fixed 256): HTTP 200, then a non-zero gateway status.
        script.extend_from_slice(HTTP_OK);
        script.extend_from_slice(&[0x01, 0x00, 0x08]);
        // Second attempt (actual length): HTTP 200, then a valid status and KMP 301.
        script.extend_from_slice(HTTP_OK);
        script.extend_from_slice(&[0x01, 0x00, 0x00]);
        script.extend_from_slice(SYNTHETIC_KMP_301);

        let mut io = ScriptedIo::new(&script);
        let outcome = handshake(&mut io, "vpn.example.net", "aevan-host", None).expect("handshake");

        assert!(outcome.succeeded());
        assert!(outcome.fallback_used());
        assert_eq!(outcome.attempts.len(), 2);
        assert_eq!(outcome.working_variant, Some(ContentLengthVariant::Actual));
        assert_eq!(outcome.attempts[0].status, Some(8));
        assert_eq!(outcome.attempts[0].variant, ContentLengthVariant::Fixed256);
        assert_eq!(outcome.attempts[1].variant, ContentLengthVariant::Actual);

        let text = String::from_utf8_lossy(&io.written);
        assert_eq!(text.matches("POST /dana/js?prot=1&svc=4").count(), 2);
        assert!(text.contains("Content-Length: 256\r\n"));
        assert!(
            text.contains("NCP-Version: 3\r\n"),
            "the oNCP request must advertise NCP-Version 3, or the gateway answers status 1"
        );
    }

    #[test]
    fn keeps_partial_bytes_and_the_read_offset_after_a_transport_eof() {
        let mut io = ScriptedIo::new(HTTP_OK);
        let outcome = handshake(&mut io, "host", "aevan-host", None).expect("handshake");

        assert!(!outcome.succeeded());
        assert!(outcome.transport_failed());
        assert_eq!(outcome.attempts.len(), 2);

        let first = &outcome.attempts[0];
        assert_eq!(first.response_bytes, HTTP_OK);
        assert_eq!(first.read_offset, Some(HTTP_OK.len()));
        assert_eq!(first.response_bytes.len(), HTTP_OK.len());
        assert!(first.transport_error);
        assert!(first
            .failure
            .as_deref()
            .expect("failure")
            .contains("transport read"));
    }

    #[test]
    fn reports_the_status_and_frames_when_both_attempts_fail() {
        let mut script = Vec::new();
        script.extend_from_slice(HTTP_OK);
        script.extend_from_slice(&[0x01, 0x00, 0x08]);
        script.extend_from_slice(HTTP_OK);
        script.extend_from_slice(&[0x01, 0x00, 0x09]);

        let mut io = ScriptedIo::new(&script);
        let outcome = handshake(&mut io, "host", "aevan-host", None).expect("handshake");

        assert!(!outcome.succeeded());
        assert_eq!(outcome.working_variant, None);
        let last = outcome.last_attempt().expect("attempt");
        assert_eq!(last.http_status, Some(200));
        assert_eq!(last.status, Some(9));
        assert!(last.frames.is_empty());
        assert!(last.failure.as_deref().expect("failure").contains("0x09"));
    }
}
