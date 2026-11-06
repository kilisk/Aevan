//! Stage 3 — typed NCP (oNCP) configuration.
//!
//! Network Connect configuration is **not** a text body. The gateway sends
//! binary KMP messages inside the TLS stream after the HTTP login. This module
//! decodes the framing and the TLV payload into [`NcpConfig`].
//!
//! ## Wire layout
//!
//! The layout below is taken from the reference implementation's documented
//! layout (`oncp.c`: read for byte layout, written independently here). Every
//! offset this decoder relies on is marked *confirmed* when the reference code
//! reads it; constants that are only checked for equality are marked
//! *inferred*.
//!
//! ```text
//! TLS record:
//!   0..2    record length, little-endian, excluding these two bytes  confirmed
//!   2..22   KMP header, 20 bytes                                    confirmed
//!     +6    message number, big-endian u16                          confirmed
//!           301 = configuration, 302 = ESP negotiation, 303 = reply
//!     +8    ten bytes the reference checks as 01 00 00 00 00 00 00 00 00 00
//!           (not interpreted here; inferred to be a constant tag)
//!     +18   KMP payload length, big-endian u16                      confirmed
//!   22..    KMP payload: one or more group blocks
//! ```
//!
//! ```text
//! Group block (confirmed):
//!   u16 group | u32 group_length | group_length bytes of attributes
//!
//! Attribute (confirmed):
//!   u16 attr | u32 attribute_length | value bytes
//! ```
//!
//! The simpler flat record form `u16 group, u16 attr, u32 length, value` that
//! the M1 task describes is also accepted by [`decode_flat_attributes`]. Real
//! oNCP messages use the nested group blocks above; the flat form is kept for
//! callers that already have a flattened attribute stream.
//!
//! ## Attribute numbers
//!
//! These are the values this decoder asserts, derived from the reference
//! layout, not guessed:
//!
//! | group | attr | meaning | length |
//! |---|---|---|---|
//! | 1 | 1 | assigned internal IPv4 address | 4 |
//! | 1 | 2 | netmask | 4 |
//! | 1 | 3 | internal gateway | 4 |
//! | 2 | 1 | DNS server | 4 |
//! | 2 | 2 | DNS search domain | variable |
//! | 3 | 3 | split-include route (address + netmask) | 8 |
//! | 3 | 4 | split-exclude route (address + netmask) | 8 |
//! | 4 | 1 | WINS server | 4 |
//! | 6 | 2 | MTU | 4 |
//! | 7 | 1 | outbound ESP SPI | 4 |
//! | 7 | 2 | ESP key block (encryption + HMAC keys) | 0x40 |
//! | 8 | 1 | ESP encryption: 0x02 AES-128-CBC, 0x05 AES-256-CBC | 1 |
//! | 8 | 2 | ESP authentication: 0x01 HMAC-MD5, 0x02 HMAC-SHA1 | 1 |
//! | 8 | 3 | ESP compression: 0 disabled, non-zero LZO | 1 |
//! | 8 | 4 | ESP UDP port | 2 |
//! | 8 | 5 | ESP key lifetime in bytes | 4 |
//! | 8 | 6 | ESP key lifetime in seconds | 4 |
//! | 8 | 9 | ESP-to-SSL fallback seconds | 4 |
//! | 8 | 10 | replay protection (non-zero = enabled) | 4 |
//!
//! The oNCP reference layout is IPv4-only for Network Connect; there is no
//! confirmed IPv6 attribute in it. [`NcpConfig::ipv6`] remains available for a
//! future capture that supplies one.
//!
//! Unknown groups and attributes are recorded as metadata and do not fail the
//! decode. A known attribute with the wrong length is a typed error.
//!
//! ## Secrets
//!
//! Group 7/attr 2 is live ESP key material. It is accepted and moved into
//! [`EspKeyBlock`], which zeroizes on drop, has a redacted `Debug`, and is not
//! serialised. Neither the raw [`Attribute`] debug output nor [`NcpConfig`]'s
//! JSON or `Debug` output contains the key bytes.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use zeroize::Zeroizing;

/// A parsed oNCP configuration.
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
pub struct NcpConfig {
    /// Assigned IPv4 address, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<AssignedV4>,
    /// Assigned IPv6 address, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<AssignedV6>,
    /// Routes the gateway wants included in the tunnel.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub split_routes: Vec<Route>,
    /// Routes the gateway wants excluded from the tunnel.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_routes: Vec<Route>,
    /// IPv4 and IPv6 DNS servers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<IpAddr>,
    /// WINS servers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub wins: Vec<Ipv4Addr>,
    /// DNS search domains.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
    /// Tunnel MTU.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// ESP proposal, when the gateway offered one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esp: Option<EspProposal>,
    /// ESP-to-SSL fallback timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_timeout_secs: Option<u64>,
    /// Gateway address, when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    /// Unknown attributes, recorded by group/attribute/length only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unknown_attributes: Vec<UnknownAttribute>,
    /// ESP key material. Deliberately never serialised and never rendered.
    #[serde(skip)]
    esp_key_block: Option<EspKeyBlock>,
}

impl fmt::Debug for NcpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NcpConfig")
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .field("split_routes", &self.split_routes)
            .field("exclude_routes", &self.exclude_routes)
            .field("dns", &self.dns)
            .field("wins", &self.wins)
            .field("search_domains", &self.search_domains)
            .field("mtu", &self.mtu)
            .field("esp", &self.esp)
            .field("fallback_timeout_secs", &self.fallback_timeout_secs)
            .field("gateway", &self.gateway)
            .field("unknown_attributes", &self.unknown_attributes)
            .field("esp_key_block_present", &self.esp_key_block.is_some())
            .finish()
    }
}

impl NcpConfig {
    /// Decode a KMP-framed oNCP configuration message, or a bare TLV payload.
    ///
    /// A KMP frame must be message 301 (configuration). A bare payload is
    /// accepted for offline fixtures and for callers that have already removed
    /// the framing.
    pub fn parse_binary(input: &[u8]) -> Result<Self, NcpError> {
        if looks_like_text(input) {
            return Err(NcpError::TextInput);
        }

        let payload = if looks_like_kmp(input) {
            let message = decode_kmp_message(input)?;
            if message.number != KMP_CONFIG {
                return Err(NcpError::UnexpectedKmpMessage {
                    actual: message.number,
                });
            }
            message.payload
        } else if input.len() >= 22 && decode_kmp_message(input).is_ok() {
            let message = decode_kmp_message(input)?;
            return Err(NcpError::UnexpectedKmpMessage {
                actual: message.number,
            });
        } else {
            input
        };

        let attributes = decode_attributes(payload)?;
        Self::from_attributes(attributes)
    }

    /// Map decoded attributes onto the typed configuration.
    ///
    /// This is public so a caller that has already decoded a flat attribute
    /// stream can reuse the mapping and its length checks.
    pub fn from_attributes(attributes: Vec<Attribute>) -> Result<Self, NcpError> {
        if attributes.is_empty() {
            return Err(NcpError::Empty);
        }

        let mut config = Self::default();
        for attribute in attributes {
            let Attribute { group, attr, value } = attribute;
            match (group, attr) {
                (1, 1) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    ipv4_mut(&mut config).address = ipv4_from(bytes);
                }
                (1, 2) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    let netmask = ipv4_from(bytes);
                    let assigned = ipv4_mut(&mut config);
                    assigned.netmask = Some(netmask);
                    if assigned.prefix_len.is_none() {
                        assigned.prefix_len = prefix_from_netmask(netmask);
                    }
                }
                (1, 3) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    config.gateway = Some(IpAddr::V4(ipv4_from(bytes)));
                }
                (2, 1) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    push_unique(&mut config.dns, IpAddr::V4(ipv4_from(bytes)));
                }
                (2, 2) => {
                    let text = String::from_utf8_lossy(&value);
                    for domain in text.trim_end_matches('\0').split(',') {
                        let domain = domain.trim();
                        if !domain.is_empty()
                            && !config
                                .search_domains
                                .iter()
                                .any(|existing| existing == domain)
                        {
                            config.search_domains.push(domain.to_owned());
                        }
                    }
                }
                (3, 3) => {
                    let route = route_from_pair(&value, group, attr)?;
                    push_unique(&mut config.split_routes, route);
                }
                (3, 4) => {
                    let route = route_from_pair(&value, group, attr)?;
                    push_unique(&mut config.exclude_routes, route);
                }
                (4, 1) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    push_unique(&mut config.wins, ipv4_from(bytes));
                }
                (6, 2) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    let mtu = u32_from(bytes);
                    config.mtu = u16::try_from(mtu).ok();
                    if config.mtu.is_none() {
                        return Err(NcpError::UnsupportedValue {
                            group,
                            attr,
                            value: u8::try_from(mtu).unwrap_or(u8::MAX),
                        });
                    }
                }
                (7, 1) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    esp_mut(&mut config).outbound_spi = Some(u32_from(bytes));
                }
                (7, 2) => {
                    exact_len(&value, 0x40, group, attr)?;
                    config.esp_key_block = Some(EspKeyBlock::new(value));
                }
                (8, 1) => {
                    let bytes = exact_len(&value, 1, group, attr)?;
                    esp_mut(&mut config).encryption = Some(
                        EspEncryption::from_wire(bytes[0]).ok_or(NcpError::UnsupportedValue {
                            group,
                            attr,
                            value: bytes[0],
                        })?,
                    );
                }
                (8, 2) => {
                    let bytes = exact_len(&value, 1, group, attr)?;
                    esp_mut(&mut config).authentication =
                        Some(EspAuthentication::from_wire(bytes[0]).ok_or(
                            NcpError::UnsupportedValue {
                                group,
                                attr,
                                value: bytes[0],
                            },
                        )?);
                }
                (8, 3) => {
                    let bytes = exact_len(&value, 1, group, attr)?;
                    esp_mut(&mut config).compression = Some(EspCompression::from_wire(bytes[0]));
                }
                (8, 4) => {
                    let bytes = exact_len(&value, 2, group, attr)?;
                    esp_mut(&mut config).udp_port = Some(u16::from_be_bytes([bytes[0], bytes[1]]));
                }
                (8, 5) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    esp_mut(&mut config).lifetime_bytes = Some(u32_from(bytes));
                }
                (8, 6) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    esp_mut(&mut config).lifetime_seconds = Some(u32_from(bytes));
                }
                (8, 9) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    config.fallback_timeout_secs = Some(u64::from(u32_from(bytes)));
                }
                (8, 10) => {
                    let bytes = exact_len(&value, 4, group, attr)?;
                    esp_mut(&mut config).replay_protection = Some(u32_from(bytes) != 0);
                }
                _ => config.unknown_attributes.push(UnknownAttribute {
                    group,
                    attr,
                    length: value.len(),
                }),
            }
        }

        if let Some(ipv4) = &mut config.ipv4 {
            if ipv4.prefix_len.is_none() {
                ipv4.prefix_len = ipv4.netmask.and_then(prefix_from_netmask);
            }
        }

        Ok(config)
    }

    /// The ESP key block, if the gateway supplied one.
    ///
    /// The returned bytes are live key material; callers must not log, print or
    /// serialise them.
    pub fn esp_key_block(&self) -> Option<&[u8]> {
        self.esp_key_block.as_ref().map(|block| block.as_bytes())
    }

    /// Whether the ESP key block was supplied.
    pub fn has_esp_key_block(&self) -> bool {
        self.esp_key_block.is_some()
    }
}

/// Assigned IPv4 address and netmask/prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssignedV4 {
    /// Address.
    pub address: Ipv4Addr,
    /// Netmask, if the gateway supplied one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netmask: Option<Ipv4Addr>,
    /// Prefix length, derived from a netmask.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
}

/// Assigned IPv6 address and prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssignedV6 {
    /// Address.
    pub address: Ipv6Addr,
    /// Prefix length, if the gateway supplied one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
}

/// One route in a split-tunnel list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route {
    /// Network address.
    pub network: IpAddr,
    /// Prefix length.
    pub prefix_len: u8,
}

/// ESP encryption transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EspEncryption {
    /// AES-128-CBC, wire value 0x02.
    #[serde(rename = "AES-128-CBC")]
    Aes128Cbc,
    /// AES-256-CBC, wire value 0x05.
    #[serde(rename = "AES-256-CBC")]
    Aes256Cbc,
}

impl EspEncryption {
    /// Map the oNCP wire value. Values come from the reference layout.
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0x02 => Some(Self::Aes128Cbc),
            0x05 => Some(Self::Aes256Cbc),
            _ => None,
        }
    }

    /// Stable display name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes256Cbc => "AES-256-CBC",
        }
    }

    /// Encryption key length in bytes for this transform (RFC 3602).
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes256Cbc => 32,
        }
    }

    /// AES block size in bytes.
    pub const fn block_len(self) -> usize {
        16
    }
}

impl fmt::Display for EspEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ESP authentication transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EspAuthentication {
    /// HMAC-MD5, wire value 0x01.
    #[serde(rename = "MD5")]
    HmacMd5,
    /// HMAC-SHA1, wire value 0x02.
    #[serde(rename = "SHA1")]
    HmacSha1,
}

impl EspAuthentication {
    /// Map the oNCP wire value. Values come from the reference layout.
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::HmacMd5),
            0x02 => Some(Self::HmacSha1),
            _ => None,
        }
    }

    /// Stable display name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HmacMd5 => "MD5",
            Self::HmacSha1 => "SHA1",
        }
    }

    /// HMAC key length in bytes used by the reference and by RFC 2202.
    pub const fn key_len(self) -> usize {
        match self {
            Self::HmacMd5 => 16,
            Self::HmacSha1 => 20,
        }
    }

    /// Truncated ICV length in bytes.
    ///
    /// Both transforms use the 96-bit form: HMAC-MD5-96 (RFC 2403) and
    /// HMAC-SHA-1-96 (RFC 2404). The reference truncates both HMAC-MD5 and
    /// HMAC-SHA1 to 12 bytes; the SHA1 ICV length follows the standards and
    /// the reference, not a wire capture.
    ///
    pub const fn icv_len(self) -> usize {
        match self {
            Self::HmacMd5 | Self::HmacSha1 => 12,
        }
    }
}

impl fmt::Display for EspAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ESP compression transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EspCompression {
    /// Compression disabled (wire value 0).
    #[serde(rename = "none")]
    Disabled,
    /// LZO (any non-zero wire value in the reference).
    #[serde(rename = "LZO")]
    Lzo,
}

impl EspCompression {
    /// Map the oNCP wire value.
    pub const fn from_wire(value: u8) -> Self {
        if value == 0 {
            Self::Disabled
        } else {
            Self::Lzo
        }
    }

    /// Stable display name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "none",
            Self::Lzo => "LZO",
        }
    }
}

impl fmt::Display for EspCompression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The ESP proposal the gateway offered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EspProposal {
    /// Encryption transform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EspEncryption>,
    /// Authentication transform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<EspAuthentication>,
    /// Compression transform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<EspCompression>,
    /// UDP port for ESP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_port: Option<u16>,
    /// ESP key lifetime in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime_bytes: Option<u32>,
    /// ESP key lifetime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime_seconds: Option<u32>,
    /// Replay protection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_protection: Option<bool>,
    /// Outbound ESP SPI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_spi: Option<u32>,
}

/// One decoded TLV attribute.
#[derive(Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Attribute group.
    pub group: u16,
    /// Attribute number within the group.
    pub attr: u16,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

impl Attribute {
    /// The raw value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attribute")
            .field("group", &self.group)
            .field("attr", &self.attr)
            .field("length", &self.value.len())
            .finish()
    }
}

/// Metadata for an attribute this build does not interpret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnknownAttribute {
    /// Attribute group.
    pub group: u16,
    /// Attribute number within the group.
    pub attr: u16,
    /// Value length in bytes.
    pub length: usize,
}

/// A decoded KMP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmpMessage<'a> {
    /// KMP message number (301 configuration, 302 ESP negotiation, 303 reply).
    pub number: u16,
    /// KMP payload, with the 20-byte KMP header removed.
    pub payload: &'a [u8],
    /// Declared TLS-record length, excluding the two-byte prefix.
    pub record_length: usize,
}

/// The ESP key block. Zeroized on drop, redacted in `Debug`, never serialised.
#[derive(Clone, PartialEq, Eq)]
pub struct EspKeyBlock(Zeroizing<Vec<u8>>);

impl EspKeyBlock {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Raw key bytes. Callers must not log, print or serialise them.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Length of the key block in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key block is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for EspKeyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspKeyBlock")
            .field("redacted", &true)
            .field("length", &self.0.len())
            .finish()
    }
}

/// Errors from the oNCP decoder.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NcpError {
    /// A TLV record extends past the end of its buffer or group.
    #[error("truncated oNCP TLV at offset {offset}: need {needed} bytes, {available} available")]
    Truncated {
        /// Byte offset where the record starts.
        offset: usize,
        /// Bytes required by the record header/value.
        needed: usize,
        /// Bytes remaining.
        available: usize,
    },
    /// A known attribute had the wrong length.
    #[error("oNCP attribute {group}/{attr} has length {actual}, expected {expected}")]
    WrongLength {
        /// Attribute group.
        group: u16,
        /// Attribute number.
        attr: u16,
        /// Required length.
        expected: usize,
        /// Observed length.
        actual: usize,
    },
    /// A known attribute carried a value this build cannot map.
    #[error("oNCP attribute {group}/{attr} has unsupported value {value}")]
    UnsupportedValue {
        /// Attribute group.
        group: u16,
        /// Attribute number.
        attr: u16,
        /// Observed value.
        value: u8,
    },
    /// A split route's netmask was not contiguous.
    #[error("oNCP route {group}/{attr} has a non-contiguous netmask")]
    InvalidNetmask {
        /// Attribute group.
        group: u16,
        /// Attribute number.
        attr: u16,
    },
    /// The TLS-record length prefix did not match the buffer.
    #[error("KMP record length {declared} does not match buffer length {actual}")]
    RecordLength {
        /// Declared total length including the two-byte prefix.
        declared: usize,
        /// Actual buffer length.
        actual: usize,
    },
    /// The KMP payload length exceeded the record.
    #[error("KMP payload length {declared} exceeds available {available}")]
    KmpLength {
        /// Declared payload length.
        declared: usize,
        /// Payload bytes actually available.
        available: usize,
    },
    /// A KMP frame was not the configuration message.
    #[error("expected KMP message 301 (configuration), got {actual}")]
    UnexpectedKmpMessage {
        /// Observed message number.
        actual: u16,
    },
    /// The input was text, not binary oNCP.
    #[error(
        "NCP configuration is binary oNCP/KMP/TLV, not text; the gateway sends it in the \
         oNCP handshake after login (see crates/aevan-nc/tests/fixtures/ncp-config-kmp.bin \
         for a synthetic example)"
    )]
    TextInput,
    /// No attribute records were present.
    #[error("NCP configuration contains no attribute records")]
    Empty,
}

/// KMP message number for the configuration message.
pub const KMP_CONFIG: u16 = 301;
/// KMP message number for ESP negotiation.
pub const KMP_ESP_NEGOTIATION: u16 = 302;
/// KMP message number for the client configuration reply.
pub const KMP_CLIENT_CONFIG: u16 = 303;

/// Whether `input` begins with a plausible KMP frame for a known message.
pub fn looks_like_kmp(input: &[u8]) -> bool {
    if input.len() < 22 {
        return false;
    }
    let le = usize::from(u16::from_le_bytes([input[0], input[1]]));
    let be = usize::from(u16::from_be_bytes([input[0], input[1]]));
    let framed = le + 2 == input.len() || be + 2 == input.len();
    let number = u16::from_be_bytes([input[8], input[9]]);
    framed && matches!(number, KMP_CONFIG | KMP_ESP_NEGOTIATION | KMP_CLIENT_CONFIG)
}

/// Decode the two-byte record prefix and the 20-byte KMP header.
///
/// The reference sends the outer record length little-endian; a big-endian
/// prefix is accepted only when the little-endian reading does not match the
/// buffer, so a real capture is never reinterpreted.
pub fn decode_kmp_message(input: &[u8]) -> Result<KmpMessage<'_>, NcpError> {
    const HEADER: usize = 20;
    if input.len() < 2 + HEADER {
        return Err(NcpError::Truncated {
            offset: 0,
            needed: 2 + HEADER,
            available: input.len(),
        });
    }

    let le = usize::from(u16::from_le_bytes([input[0], input[1]]));
    let be = usize::from(u16::from_be_bytes([input[0], input[1]]));
    let declared = if le + 2 == input.len() {
        le
    } else if be + 2 == input.len() {
        be
    } else {
        return Err(NcpError::RecordLength {
            declared: le + 2,
            actual: input.len(),
        });
    };

    let kmp = &input[2..2 + declared];
    if kmp.len() < HEADER {
        return Err(NcpError::Truncated {
            offset: 2,
            needed: HEADER,
            available: kmp.len(),
        });
    }

    let number = u16::from_be_bytes([kmp[6], kmp[7]]);
    let payload_len = usize::from(u16::from_be_bytes([kmp[18], kmp[19]]));
    let available = kmp.len() - HEADER;
    if payload_len > available {
        return Err(NcpError::KmpLength {
            declared: payload_len,
            available,
        });
    }

    Ok(KmpMessage {
        number,
        payload: &kmp[HEADER..HEADER + payload_len],
        record_length: declared,
    })
}

/// Decode an oNCP payload into attributes.
///
/// Real payloads are nested group blocks. The flat record form is also tried,
/// because the M1 task describes that layout. A structural failure is reported
/// only when neither form parses.
pub fn decode_attributes(payload: &[u8]) -> Result<Vec<Attribute>, NcpError> {
    let grouped = decode_grouped_attributes(payload);
    let flat = decode_flat_attributes(payload);

    match (grouped, flat) {
        (Ok(grouped), Ok(flat)) => {
            if grouped.is_empty() || known_count(&flat) > known_count(&grouped) {
                Ok(flat)
            } else {
                Ok(grouped)
            }
        }
        (Ok(grouped), Err(_)) => Ok(grouped),
        (Err(_), Ok(flat)) => Ok(flat),
        (Err(grouped), Err(_)) => Err(grouped),
    }
}

/// Decode flat attribute records: `u16 group, u16 attr, u32 length, value`.
///
/// This is the simplified record form described by the M1 task. Real oNCP
/// messages use [`decode_attributes`]'s nested group blocks.
pub fn decode_flat_attributes(payload: &[u8]) -> Result<Vec<Attribute>, NcpError> {
    let mut attributes = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let header = take(payload, offset, 8)?;
        let group = u16::from_be_bytes([header[0], header[1]]);
        let attr = u16::from_be_bytes([header[2], header[3]]);
        let length = usize::try_from(u32::from_be_bytes([
            header[4], header[5], header[6], header[7],
        ]))
        .map_err(|_| NcpError::Truncated {
            offset,
            needed: usize::MAX,
            available: payload.len() - offset,
        })?;

        let value = take(payload, offset + 8, length)?;
        attributes.push(Attribute {
            group,
            attr,
            value: value.to_vec(),
        });
        offset += 8 + length;
    }

    Ok(attributes)
}

/// Decode the nested group-block form used by real oNCP messages.
///
/// This is the strict decoder: it does not fall back to the flat form. Use it
/// when the message is known to use group blocks, such as KMP 302.
pub fn decode_grouped_attributes(payload: &[u8]) -> Result<Vec<Attribute>, NcpError> {
    let mut attributes = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let header = take(payload, offset, 6)?;
        let group = u16::from_be_bytes([header[0], header[1]]);
        let group_len = usize::try_from(u32::from_be_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .map_err(|_| NcpError::Truncated {
            offset,
            needed: usize::MAX,
            available: payload.len() - offset,
        })?;

        let body_start = offset + 6;
        let body_end = body_start
            .checked_add(group_len)
            .filter(|end| *end <= payload.len())
            .ok_or(NcpError::Truncated {
                offset,
                needed: 6 + group_len,
                available: payload.len() - offset,
            })?;

        let mut inner = body_start;
        while inner < body_end {
            let attr_header = take(payload, inner, 6)?;
            let attr = u16::from_be_bytes([attr_header[0], attr_header[1]]);
            let attr_len = usize::try_from(u32::from_be_bytes([
                attr_header[2],
                attr_header[3],
                attr_header[4],
                attr_header[5],
            ]))
            .map_err(|_| NcpError::Truncated {
                offset: inner,
                needed: usize::MAX,
                available: body_end - inner,
            })?;

            let value_start = inner + 6;
            let value_end = value_start
                .checked_add(attr_len)
                .filter(|end| *end <= body_end)
                .ok_or(NcpError::Truncated {
                    offset: inner,
                    needed: 6 + attr_len,
                    available: body_end - inner,
                })?;

            attributes.push(Attribute {
                group,
                attr,
                value: payload[value_start..value_end].to_vec(),
            });
            inner = value_end;
        }

        offset = body_end;
    }

    Ok(attributes)
}

fn take(input: &[u8], offset: usize, needed: usize) -> Result<&[u8], NcpError> {
    let available = input.len().saturating_sub(offset);
    if available < needed {
        return Err(NcpError::Truncated {
            offset,
            needed,
            available,
        });
    }
    Ok(&input[offset..offset + needed])
}

fn known_count(attributes: &[Attribute]) -> usize {
    attributes
        .iter()
        .filter(|attribute| is_known(attribute.group, attribute.attr))
        .count()
}

fn is_known(group: u16, attr: u16) -> bool {
    matches!(
        (group, attr),
        (1, 1)
            | (1, 2)
            | (1, 3)
            | (2, 1)
            | (2, 2)
            | (3, 3)
            | (3, 4)
            | (4, 1)
            | (6, 2)
            | (7, 1)
            | (7, 2)
            | (8, 1)
            | (8, 2)
            | (8, 3)
            | (8, 4)
            | (8, 5)
            | (8, 6)
            | (8, 9)
            | (8, 10)
    )
}

fn exact_len(value: &[u8], expected: usize, group: u16, attr: u16) -> Result<&[u8], NcpError> {
    if value.len() != expected {
        return Err(NcpError::WrongLength {
            group,
            attr,
            expected,
            actual: value.len(),
        });
    }
    Ok(value)
}

fn ipv4_from(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn u32_from(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn ipv4_mut(config: &mut NcpConfig) -> &mut AssignedV4 {
    config.ipv4.get_or_insert(AssignedV4 {
        address: Ipv4Addr::UNSPECIFIED,
        netmask: None,
        prefix_len: None,
    })
}

fn esp_mut(config: &mut NcpConfig) -> &mut EspProposal {
    config.esp.get_or_insert_with(EspProposal::default)
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn route_from_pair(value: &[u8], group: u16, attr: u16) -> Result<Route, NcpError> {
    let bytes = exact_len(value, 8, group, attr)?;
    let address = ipv4_from(&bytes[0..4]);
    let netmask = ipv4_from(&bytes[4..8]);
    let prefix_len =
        prefix_from_netmask(netmask).ok_or(NcpError::InvalidNetmask { group, attr })?;
    let network = Ipv4Addr::from(u32::from(address) & u32::from(netmask));
    Ok(Route {
        network: IpAddr::V4(network),
        prefix_len,
    })
}

fn prefix_from_netmask(netmask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(netmask);
    let prefix = bits.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (bits == expected).then_some(prefix)
}

fn looks_like_text(input: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };
    !text.is_empty()
        && !text.contains('\0')
        && text
            .chars()
            .all(|ch| ch == '\n' || ch == '\r' || ch == '\t' || !ch.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    // SYNTHETIC FIXTURE — built from observed values plus a synthetic ESP key
    // block, not a captured gateway response. The blob also carries an
    // unknown group 0xFFFF attribute whose value is the honest fixture note.
    const CONFIG: &[u8] = include_bytes!("../tests/fixtures/ncp-config-kmp.bin");

    #[test]
    fn decodes_the_synthetic_e13_fixture() {
        let config = NcpConfig::parse_binary(CONFIG).expect("parse");

        let ipv4 = config.ipv4.as_ref().expect("ipv4");
        assert_eq!(ipv4.address, Ipv4Addr::new(10, 251, 98, 43));
        assert_eq!(ipv4.netmask, Some(Ipv4Addr::new(255, 255, 255, 255)));
        assert_eq!(ipv4.prefix_len, Some(32));
        assert_eq!(config.gateway, Some("10.200.200.200".parse().expect("ip")));

        assert_eq!(
            config.dns,
            vec![
                "10.251.3.18".parse::<IpAddr>().expect("ip"),
                "10.249.10.13".parse::<IpAddr>().expect("ip"),
            ]
        );

        let routes: Vec<(String, u8)> = config
            .split_routes
            .iter()
            .map(|route| (route.network.to_string(), route.prefix_len))
            .collect();
        assert_eq!(
            routes,
            vec![
                ("10.0.0.0".to_owned(), 8),
                ("172.30.0.0".to_owned(), 21),
                ("172.30.8.0".to_owned(), 24),
                ("172.30.6.0".to_owned(), 24),
            ]
        );

        assert_eq!(config.mtu, Some(1396));
        let esp = config.esp.as_ref().expect("esp");
        assert_eq!(esp.encryption, Some(EspEncryption::Aes128Cbc));
        assert_eq!(esp.authentication, Some(EspAuthentication::HmacSha1));
        assert_eq!(esp.compression, Some(EspCompression::Disabled));
        assert_eq!(esp.udp_port, Some(4500));
        assert_eq!(esp.outbound_spi, Some(0x1A2B_3C4D));
        assert_eq!(config.fallback_timeout_secs, Some(15));
        assert!(config.has_esp_key_block());
        assert_eq!(config.esp_key_block().expect("key block").len(), 0x40);
    }

    #[test]
    fn tolerates_unknown_groups_and_attributes() {
        let config = NcpConfig::parse_binary(CONFIG).expect("parse");
        let unknown = config
            .unknown_attributes
            .iter()
            .find(|attribute| attribute.group == 0xFFFF && attribute.attr == 1)
            .expect("fixture note attribute");
        assert!(unknown.length > 0);

        let attributes = vec![
            Attribute {
                group: 0x1234,
                attr: 9,
                value: vec![1, 2, 3],
            },
            Attribute {
                group: 6,
                attr: 2,
                value: 1400u32.to_be_bytes().to_vec(),
            },
        ];
        let config = NcpConfig::from_attributes(attributes).expect("parse");
        assert_eq!(config.mtu, Some(1400));
        assert_eq!(
            config.unknown_attributes,
            vec![UnknownAttribute {
                group: 0x1234,
                attr: 9,
                length: 3,
            }]
        );
    }

    #[test]
    fn rejects_truncated_records() {
        let truncated = [0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00];
        let error = decode_flat_attributes(&truncated).expect_err("must fail");
        assert!(matches!(error, NcpError::Truncated { .. }));

        let error = decode_kmp_message(&CONFIG[..21]).expect_err("must fail");
        assert!(matches!(error, NcpError::Truncated { .. }));
    }

    #[test]
    fn rejects_a_wrong_length_for_a_known_attribute() {
        let attributes = vec![Attribute {
            group: 6,
            attr: 2,
            value: vec![0x05, 0x78],
        }];
        let error = NcpConfig::from_attributes(attributes).expect_err("must fail");
        assert_eq!(
            error,
            NcpError::WrongLength {
                group: 6,
                attr: 2,
                expected: 4,
                actual: 2,
            }
        );

        let flat = [0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x05, 0x78];
        let error = NcpConfig::parse_binary(&flat).expect_err("must fail");
        assert_eq!(
            error,
            NcpError::WrongLength {
                group: 6,
                attr: 2,
                expected: 4,
                actual: 2,
            }
        );
    }

    #[test]
    fn accepts_kmp_301_and_refuses_another_message() {
        let message = decode_kmp_message(CONFIG).expect("kmp");
        assert_eq!(message.number, KMP_CONFIG);
        assert!(!message.payload.is_empty());

        let mut other = CONFIG.to_vec();
        other[8..10].copy_from_slice(&KMP_ESP_NEGOTIATION.to_be_bytes());
        let error = NcpConfig::parse_binary(&other).expect_err("must fail");
        assert_eq!(
            error,
            NcpError::UnexpectedKmpMessage {
                actual: KMP_ESP_NEGOTIATION,
            }
        );
    }

    #[test]
    fn key_material_is_never_rendered() {
        let config = NcpConfig::parse_binary(CONFIG).expect("parse");
        assert!(config.has_esp_key_block());

        let debug = format!("{config:?}");
        let json = serde_json::to_string(&config).expect("json");
        let key = config.esp_key_block().expect("key block");

        let marker = b"AEVAN-SYNTHETIC-ESP-KEY-DO-NOT-LEAK";
        let marker = std::str::from_utf8(marker).expect("marker");
        let marker_hex = marker
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert!(!debug.contains(marker));
        assert!(!debug.contains(&marker_hex));
        assert!(!json.contains(marker));
        assert!(!json.contains(&marker_hex));
        assert!(!json.to_ascii_lowercase().contains("esp_key"));
        assert!(!format!("{key:?}").contains(marker));
    }

    #[test]
    fn maps_lifetimes_replay_excludes_wins_and_search_domains() {
        let attributes = vec![
            Attribute {
                group: 2,
                attr: 2,
                value: b"corp.example,gov.example\0".to_vec(),
            },
            Attribute {
                group: 3,
                attr: 4,
                value: [[192, 168, 0, 0].as_slice(), [255, 255, 0, 0].as_slice()].concat(),
            },
            Attribute {
                group: 4,
                attr: 1,
                value: vec![10, 0, 0, 10],
            },
            Attribute {
                group: 8,
                attr: 5,
                value: 1_000_000u32.to_be_bytes().to_vec(),
            },
            Attribute {
                group: 8,
                attr: 6,
                value: 3600u32.to_be_bytes().to_vec(),
            },
            Attribute {
                group: 8,
                attr: 10,
                value: 1u32.to_be_bytes().to_vec(),
            },
        ];
        let config = NcpConfig::from_attributes(attributes).expect("parse");
        assert_eq!(
            config.search_domains,
            vec!["corp.example".to_owned(), "gov.example".to_owned()]
        );
        assert_eq!(config.exclude_routes.len(), 1);
        assert_eq!(config.exclude_routes[0].network.to_string(), "192.168.0.0");
        assert_eq!(config.exclude_routes[0].prefix_len, 16);
        assert_eq!(config.wins, vec![Ipv4Addr::new(10, 0, 0, 10)]);
        let esp = config.esp.expect("esp");
        assert_eq!(esp.lifetime_bytes, Some(1_000_000));
        assert_eq!(esp.lifetime_seconds, Some(3600));
        assert_eq!(esp.replay_protection, Some(true));
    }

    #[test]
    fn text_is_rejected_with_the_binary_format_explanation() {
        let error =
            NcpConfig::parse_binary(b"INTERNAL_IP4_ADDRESS=10.0.0.1\n").expect_err("must fail");
        assert_eq!(error, NcpError::TextInput);
        assert!(error.to_string().contains("binary oNCP/KMP/TLV"));
    }

    #[test]
    fn esp_transform_wire_values_match_the_reference_layout() {
        // From the oNCP reference layout: ENC_AES_128_CBC=2, ENC_AES_256_CBC=5,
        // HMAC_MD5=1, HMAC_SHA1=2. AES-256 is not the value next to AES-128.
        assert_eq!(
            EspEncryption::from_wire(0x02),
            Some(EspEncryption::Aes128Cbc)
        );
        assert_eq!(
            EspEncryption::from_wire(0x05),
            Some(EspEncryption::Aes256Cbc)
        );
        assert_eq!(EspEncryption::from_wire(0x03), None);

        assert_eq!(
            EspAuthentication::from_wire(0x01),
            Some(EspAuthentication::HmacMd5)
        );
        assert_eq!(
            EspAuthentication::from_wire(0x02),
            Some(EspAuthentication::HmacSha1)
        );
        assert_eq!(EspAuthentication::from_wire(0x03), None);
    }
}
