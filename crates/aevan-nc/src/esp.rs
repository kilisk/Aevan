//! The ESP data plane: packet in, packet out, no sockets.
//!
//! ## Frame layout (RFC 4303 with the offered transforms)
//!
//! ```text
//! 0..4    SPI, 32-bit, network byte order
//! 4..8    sequence number, 32-bit, network byte order
//! 8..24   CBC IV, 16 bytes
//! 24..N   AES-CBC ciphertext (payload | padding | pad length | next header)
//! N..N+K  ICV (truncated HMAC), K = 12
//! ```
//!
//! The ciphertext is always a positive multiple of the AES block size. Padding
//! is `0..=15` bytes; the pad-length byte and the next-header byte follow it.
//! The ICV covers the ESP header (SPI, sequence, IV) and the ciphertext, and is
//! truncated to 96 bits for both HMAC-MD5 (RFC 2403) and HMAC-SHA1 (RFC 2404).
//! The SHA1 ICV length follows the standards and the reference, not a wire
//! capture.
//!
//! ## What is specified and what is inferred
//!
//! * Observed gateway: AES-128-CBC with HMAC-SHA1 over UDP 4500.
//! * Reference: AES-128/AES-256, MD5-96/SHA1, ESP keepalives and rekey counters.
//! * Reference (`esp.c`, read for layout): ESP header order, padding formula,
//!   HMAC coverage, ICV truncation to 12 bytes, and the next CBC IV being the
//!   last ciphertext block of the previous packet. The IV-chaining detail is an
//!   openconnect behaviour, not a capture.
//! * Inferred/offline: the keepalive payload is a typed helper, not observed
//!   gateway behaviour. The rekey direction is now live evidence: the gateway
//!   sends its own KMP 302 at the soft lifetime, and the client answers.
//!
//! ## Rekey: server-driven, with a client-initiated fallback
//!
//! Live evidence shows the gateway drives ESP rekey. At the soft lifetime it
//! sends its own KMP 302 carrying group 7/attr 1 (the client's **outbound**
//! SPI) and group 7/attr 2 (the client's 0x40-byte outbound key block), plus
//! group 8 transforms and lifetimes. That message is an instruction, not a
//! proposal: the peer expects the new outbound keys immediately.
//!
//! [`EspSession`] therefore polls the retained oNCP channel while the tunnel is
//! running. On a valid inbound 302 it installs the supplied outbound SA at
//! once, resets the outbound sequence number and IV, updates the lifetime from
//! group 8 attrs 5/6 when present, and restarts the local rekey timer from that
//! moment. The previous outbound SA is simply replaced: packet processing is
//! synchronous, so there is no queued packet that still needs the old keys.
//!
//! It then answers with its own KMP 302 proposing fresh **inbound** keys
//! followed by KMP 303, installs that inbound SA as current, and keeps the
//! previous inbound SA accepted until [`EspSessionConfig::rekey_grace`] expires
//! so packets already in flight are not lost. Only one exchange is in flight at
//! a time: an inbound 302 that arrives during an exchange still has its outbound
//! keys applied, but does not start a second proposal.
//!
//! The older client-initiated path remains as a fallback. [`RekeyPolicy`] asks
//! whether a rekey is due; [`EspSession`] generates fresh inbound keys with
//! [`EspLocalKeys`], sends KMP 302 then KMP 303, and waits for the peer to prove
//! it accepted them before switching the outbound SA. The outbound SA is
//! switched only on a KMP 303 reply or an inbound packet on the new SPI. If
//! neither arrives within the grace window, the pending inbound SA is dropped,
//! the old SAs keep running, and a retry is scheduled with backoff (60 s, then
//! 300 s). If a gateway-initiated 302 is processed first, the local timer is
//! reset and no client-initiated 302 is sent.
//!
//! ## Secrets
//!
//! [`EspKeys`] holds key material in [`SecretKey`] values: zeroized on drop,
//! redacted in `Debug`, and never serialised. No function in this module logs
//! key bytes.

use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use aes::{Aes128, Aes256};
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;

use crate::ncp::{
    EspAuthentication, EspEncryption, EspProposal, KMP_CLIENT_CONFIG, KMP_ESP_NEGOTIATION,
};
use crate::oncp::{
    client_config_reply, esp_initial_iv, esp_negotiation, parse_server_rekey, EspLocalKeys,
    EspNegotiation, ESP_KEY_BLOCK_LEN,
};
use crate::replay::{ReplayError, ReplayWindow};
use crate::secret::SecretKey;

/// AES block size and ESP CBC IV length in bytes.
pub const ESP_IV_LEN: usize = 16;
/// SPI length in bytes.
pub const ESP_SPI_LEN: usize = 4;
/// Sequence-number length in bytes.
pub const ESP_SEQUENCE_LEN: usize = 4;
/// ESP header length: SPI + sequence + IV.
pub const ESP_HEADER_LEN: usize = ESP_SPI_LEN + ESP_SEQUENCE_LEN + ESP_IV_LEN;

/// Maximum number of datagrams or device packets handled by one poll.
///
/// The cap bounds how long one wake can run before the loop re-checks the stop
/// flag and returns to the event wait. Any remainder stays queued for the next
/// poll.
pub const ESP_BATCH_MAX: usize = 64;

/// Largest UDP datagram this data plane accepts.
const ESP_MAX_DATAGRAM: usize = 65_536;

/// Worst-case ESP bytes added around one inner packet.
const ESP_WIRE_OVERHEAD: usize = ESP_HEADER_LEN + ESP_IV_LEN + 2 + 20;

/// Longest ICV any supported transform produces before truncation.
const MAX_ICV_LEN: usize = 20;

/// Next-header value for an encapsulated IPv4 packet.
pub const NEXT_HEADER_IPV4: u8 = 4;
/// Smallest inner payload that can be an IP packet (IPv4 header without options).
const MIN_IP_PACKET_LEN: usize = 20;
/// Next-header value the reference uses for LZO-compressed IPv4.
pub const NEXT_HEADER_LZO_IPV4: u8 = 5;
/// Next-header value for an encapsulated IPv6 packet.
pub const NEXT_HEADER_IPV6: u8 = 41;

/// ESP key material for one direction.
#[derive(Clone)]
pub struct EspKeys {
    encryption: EspEncryption,
    authentication: EspAuthentication,
    encryption_key: SecretKey,
    hmac_key: SecretKey,
}

impl fmt::Debug for EspKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspKeys")
            .field("encryption", &self.encryption)
            .field("authentication", &self.authentication)
            .field("encryption_key", &self.encryption_key)
            .field("hmac_key", &self.hmac_key)
            .finish()
    }
}

impl EspKeys {
    /// Build a key set, validating the key lengths for the transforms.
    pub fn new(
        encryption: EspEncryption,
        authentication: EspAuthentication,
        encryption_key: SecretKey,
        hmac_key: SecretKey,
    ) -> Result<Self, EspError> {
        if encryption_key.len() != encryption.key_len() {
            return Err(EspError::KeyLength {
                algorithm: encryption.as_str(),
                expected: encryption.key_len(),
                actual: encryption_key.len(),
            });
        }
        if hmac_key.len() != authentication.key_len() {
            return Err(EspError::KeyLength {
                algorithm: authentication.as_str(),
                expected: authentication.key_len(),
                actual: hmac_key.len(),
            });
        }
        Ok(Self {
            encryption,
            authentication,
            encryption_key,
            hmac_key,
        })
    }

    /// Build keys from an oNCP KMP 302 negotiation.
    pub fn from_negotiation(negotiation: &EspNegotiation) -> Result<Self, EspError> {
        Self::new(
            negotiation.encryption,
            negotiation.authentication,
            negotiation.encryption_key.clone(),
            negotiation.hmac_key.clone(),
        )
    }

    /// Split a 0x40-byte key block using the transforms' key lengths.
    ///
    /// The block is `encryption_key || hmac_key || unused`, as in the
    /// reference. Extra bytes after the two keys are ignored.
    pub fn from_key_block(
        block: &[u8],
        encryption: EspEncryption,
        authentication: EspAuthentication,
    ) -> Result<Self, EspError> {
        let enc_len = encryption.key_len();
        let hmac_len = authentication.key_len();
        let needed = enc_len + hmac_len;
        if block.len() < needed {
            return Err(EspError::KeyBlockTooShort {
                needed,
                actual: block.len(),
            });
        }
        Self::new(
            encryption,
            authentication,
            SecretKey::new(block[..enc_len].to_vec()),
            SecretKey::new(block[enc_len..needed].to_vec()),
        )
    }

    /// Encryption transform.
    pub const fn encryption(&self) -> EspEncryption {
        self.encryption
    }

    /// Authentication transform.
    pub const fn authentication(&self) -> EspAuthentication {
        self.authentication
    }

    /// Encryption key length in bytes.
    pub fn encryption_key_len(&self) -> usize {
        self.encryption_key.len()
    }

    /// HMAC key length in bytes.
    pub fn hmac_key_len(&self) -> usize {
        self.hmac_key.len()
    }

    /// Verify the truncated ICV over `authenticated` (header plus ciphertext).
    pub fn verify_icv(&self, authenticated: &[u8], icv: &[u8]) -> Result<(), EspError> {
        let icv_len = self.authentication.icv_len();
        if icv.len() != icv_len {
            return Err(EspError::IcvLength {
                expected: icv_len,
                actual: icv.len(),
            });
        }
        let mut expected = [0u8; MAX_ICV_LEN];
        hmac_into(
            self.authentication,
            self.hmac_key.expose(),
            authenticated,
            &mut expected,
        )?;
        if !constant_time_eq(&expected[..icv_len], icv) {
            return Err(EspError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Authenticate and decrypt one complete ESP packet.
    ///
    /// This is the stateless form. Use [`InboundSa`] when replay protection is
    /// required as well.
    pub fn decrypt_packet(&self, packet: &[u8]) -> Result<DecryptedPacket, EspError> {
        let parsed = ParsedEsp::parse(packet, self.authentication.icv_len())?;
        self.verify_icv(parsed.authenticated, parsed.icv)?;
        self.decrypt_ciphertext(&parsed)
    }

    /// Authenticate and decrypt one packet into a caller-owned plaintext
    /// buffer, borrowing the payload instead of allocating it.
    pub fn decrypt_packet_into<'a>(
        &self,
        packet: &[u8],
        output: &'a mut [u8],
    ) -> Result<DecryptedPacketView<'a>, EspError> {
        let parsed = ParsedEsp::parse(packet, self.authentication.icv_len())?;
        self.verify_icv(parsed.authenticated, parsed.icv)?;
        self.decrypt_ciphertext_into(&parsed, output)
    }

    fn decrypt_ciphertext(&self, parsed: &ParsedEsp<'_>) -> Result<DecryptedPacket, EspError> {
        let mut plaintext = vec![0u8; parsed.ciphertext.len()];
        let (spi, sequence, next_header, payload_len) = {
            let view = self.decrypt_ciphertext_into(parsed, &mut plaintext)?;
            (
                view.spi,
                view.sequence,
                view.next_header,
                view.payload.len(),
            )
        };
        plaintext.truncate(payload_len);

        Ok(DecryptedPacket {
            spi,
            sequence,
            next_header,
            payload: plaintext,
        })
    }

    fn decrypt_ciphertext_into<'a>(
        &self,
        parsed: &ParsedEsp<'_>,
        output: &'a mut [u8],
    ) -> Result<DecryptedPacketView<'a>, EspError> {
        let ciphertext_len = parsed.ciphertext.len();
        if output.len() < ciphertext_len {
            return Err(EspError::OutputBufferTooSmall {
                needed: ciphertext_len,
                available: output.len(),
            });
        }
        let plaintext = &mut output[..ciphertext_len];
        plaintext.copy_from_slice(parsed.ciphertext);
        aes_cbc_decrypt(
            self.encryption,
            self.encryption_key.expose(),
            &parsed.iv,
            plaintext,
        )?;

        if plaintext.len() < 2 {
            return Err(EspError::InvalidPadding);
        }
        let pad_len = usize::from(plaintext[plaintext.len() - 2]);
        let next_header = plaintext[plaintext.len() - 1];
        if pad_len + 2 > plaintext.len() {
            return Err(EspError::InvalidPadding);
        }
        let payload_len = plaintext.len() - pad_len - 2;

        Ok(DecryptedPacketView {
            spi: parsed.spi,
            sequence: parsed.sequence,
            next_header,
            payload: &plaintext[..payload_len],
        })
    }
}

/// Build one ESP packet.
///
/// `payload` is the inner IP packet. `next_header` is normally
/// [`NEXT_HEADER_IPV4`] or [`NEXT_HEADER_IPV6`]. The caller owns the sequence
/// number and the IV; [`OutboundSa`] maintains both across packets.
pub fn encrypt_packet(
    keys: &EspKeys,
    spi: u32,
    sequence: u32,
    iv: &[u8; ESP_IV_LEN],
    payload: &[u8],
    next_header: u8,
) -> Result<Vec<u8>, EspError> {
    let total = esp_packet_len(payload.len(), keys.authentication.icv_len());
    let mut packet = vec![0u8; total];
    let written = encrypt_packet_into(keys, spi, sequence, iv, payload, next_header, &mut packet)?;
    debug_assert_eq!(written, total);
    Ok(packet)
}

/// Build one ESP packet into a caller-owned buffer.
///
/// Returns the number of bytes written. The buffer is reused by the live data
/// plane so a steady-state packet does not allocate.
pub fn encrypt_packet_into(
    keys: &EspKeys,
    spi: u32,
    sequence: u32,
    iv: &[u8; ESP_IV_LEN],
    payload: &[u8],
    next_header: u8,
    output: &mut [u8],
) -> Result<usize, EspError> {
    let pad_len = padding_len(payload.len());
    let ciphertext_len = payload.len() + pad_len + 2;
    let icv_len = keys.authentication.icv_len();
    let total = ESP_HEADER_LEN + ciphertext_len + icv_len;
    if output.len() < total {
        return Err(EspError::OutputBufferTooSmall {
            needed: total,
            available: output.len(),
        });
    }

    output[..ESP_SPI_LEN].copy_from_slice(&spi.to_be_bytes());
    output[ESP_SPI_LEN..ESP_SPI_LEN + ESP_SEQUENCE_LEN].copy_from_slice(&sequence.to_be_bytes());
    output[ESP_SPI_LEN + ESP_SEQUENCE_LEN..ESP_HEADER_LEN].copy_from_slice(iv);
    output[ESP_HEADER_LEN..ESP_HEADER_LEN + payload.len()].copy_from_slice(payload);

    let padding_start = ESP_HEADER_LEN + payload.len();
    for index in 0..pad_len {
        output[padding_start + index] = (index + 1) as u8;
    }
    let trailer = padding_start + pad_len;
    output[trailer] = pad_len as u8;
    output[trailer + 1] = next_header;

    let body_end = ESP_HEADER_LEN + ciphertext_len;
    aes_cbc_encrypt(
        keys.encryption,
        keys.encryption_key.expose(),
        iv,
        &mut output[ESP_HEADER_LEN..body_end],
    )?;

    let mut icv = [0u8; MAX_ICV_LEN];
    hmac_into(
        keys.authentication,
        keys.hmac_key.expose(),
        &output[..body_end],
        &mut icv,
    )?;
    output[body_end..body_end + icv_len].copy_from_slice(&icv[..icv_len]);
    Ok(total)
}

fn esp_packet_len(payload_len: usize, icv_len: usize) -> usize {
    ESP_HEADER_LEN + payload_len + padding_len(payload_len) + 2 + icv_len
}

/// Authenticate and decrypt one complete ESP packet without replay state.
///
/// This is a convenience wrapper over [`EspKeys::decrypt_packet`].
pub fn decrypt_packet(keys: &EspKeys, packet: &[u8]) -> Result<DecryptedPacket, EspError> {
    keys.decrypt_packet(packet)
}

/// Read the SPI from a packet without authenticating it.
///
/// The result is untrusted until [`InboundSa::decrypt`] succeeds; use it only
/// to select an SA.
pub fn peek_spi(packet: &[u8]) -> Option<u32> {
    packet
        .get(..ESP_SPI_LEN)
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read the sequence number from a packet without authenticating it.
pub fn peek_sequence(packet: &[u8]) -> Option<u32> {
    packet
        .get(4..8)
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// A decrypted ESP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedPacket {
    /// SPI from the ESP header.
    pub spi: u32,
    /// Sequence number from the ESP header.
    pub sequence: u32,
    /// Next-header byte from the ESP trailer.
    pub next_header: u8,
    /// Inner packet bytes.
    pub payload: Vec<u8>,
}

/// A decrypted ESP packet borrowing the caller-owned plaintext buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptedPacketView<'a> {
    /// SPI from the ESP header.
    pub spi: u32,
    /// Sequence number from the ESP header.
    pub sequence: u32,
    /// Next-header byte from the ESP trailer.
    pub next_header: u8,
    /// Inner packet bytes, valid until the output buffer is reused.
    pub payload: &'a [u8],
}

/// The send side of one ESP security association.
///
/// The sequence number starts at zero, as the reference does, and increments
/// for every packet. The SA refuses to reuse a sequence number after
/// `u32::MAX` rather than wrapping silently.
///
/// The CBC IV starts at the caller-supplied value. After each packet it becomes
/// the last ciphertext block, the same chaining the reference uses. This is an
/// inferred interop detail, not an observed gateway requirement.
pub struct OutboundSa {
    spi: u32,
    keys: EspKeys,
    next_sequence: u32,
    iv: [u8; ESP_IV_LEN],
    exhausted: bool,
}

impl fmt::Debug for OutboundSa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundSa")
            .field("spi", &format_args!("{:#010x}", self.spi))
            .field("next_sequence", &self.next_sequence)
            .field("exhausted", &self.exhausted)
            .field("keys", &self.keys)
            .finish()
    }
}

impl OutboundSa {
    /// Create a send SA with an explicit starting IV.
    pub fn new(spi: u32, keys: EspKeys, iv: [u8; ESP_IV_LEN]) -> Self {
        Self {
            spi,
            keys,
            next_sequence: 0,
            iv,
            exhausted: false,
        }
    }

    /// SPI this SA sends with.
    pub const fn spi(&self) -> u32 {
        self.spi
    }

    /// The sequence number the next packet will use.
    pub const fn next_sequence(&self) -> u32 {
        self.next_sequence
    }

    /// Whether the sequence space is exhausted.
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Keys used by this SA.
    pub const fn keys(&self) -> &EspKeys {
        &self.keys
    }

    /// Encrypt one inner packet and advance the sequence number and IV.
    pub fn encrypt(&mut self, payload: &[u8], next_header: u8) -> Result<Vec<u8>, EspError> {
        let total = esp_packet_len(payload.len(), self.keys.authentication.icv_len());
        let mut packet = vec![0u8; total];
        let written = self.encrypt_into(payload, next_header, &mut packet)?;
        debug_assert_eq!(written, total);
        Ok(packet)
    }

    /// Encrypt one inner packet into a caller-owned buffer and advance the
    /// sequence number and IV. Returns the number of bytes written.
    pub fn encrypt_into(
        &mut self,
        payload: &[u8],
        next_header: u8,
        output: &mut [u8],
    ) -> Result<usize, EspError> {
        let sequence = self.take_sequence()?;
        let total = encrypt_packet_into(
            &self.keys,
            self.spi,
            sequence,
            &self.iv,
            payload,
            next_header,
            output,
        )?;

        let ciphertext_end = total - self.keys.authentication.icv_len();
        let last_block = &output[ciphertext_end - ESP_IV_LEN..ciphertext_end];
        self.iv.copy_from_slice(last_block);
        Ok(total)
    }

    fn take_sequence(&mut self) -> Result<u32, EspError> {
        if self.exhausted {
            return Err(EspError::SequenceExhausted);
        }
        let sequence = self.next_sequence;
        if sequence == u32::MAX {
            self.exhausted = true;
        } else {
            self.next_sequence += 1;
        }
        Ok(sequence)
    }
}

impl Clone for OutboundSa {
    fn clone(&self) -> Self {
        Self {
            spi: self.spi,
            keys: self.keys.clone(),
            next_sequence: self.next_sequence,
            iv: self.iv,
            exhausted: self.exhausted,
        }
    }
}

/// The receive side of one ESP security association.
///
/// Authentication happens before the replay check, and decryption only after
/// both succeed, so unauthenticated packets cannot advance the window.
pub struct InboundSa {
    keys: EspKeys,
    replay: ReplayWindow,
}

impl fmt::Debug for InboundSa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundSa")
            .field("keys", &self.keys)
            .field("highest_sequence", &self.replay.highest())
            .finish()
    }
}

impl InboundSa {
    /// Create a receive SA with an empty replay window.
    pub fn new(keys: EspKeys) -> Self {
        Self {
            keys,
            replay: ReplayWindow::new(),
        }
    }

    /// Keys used by this SA.
    pub const fn keys(&self) -> &EspKeys {
        &self.keys
    }

    /// The replay window.
    pub const fn replay(&self) -> &ReplayWindow {
        &self.replay
    }

    /// Authenticate, check for replay, then decrypt one packet.
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<DecryptedPacket, EspError> {
        let parsed = ParsedEsp::parse(packet, self.keys.authentication.icv_len())?;
        self.keys.verify_icv(parsed.authenticated, parsed.icv)?;
        self.replay.check_and_update(u64::from(parsed.sequence))?;
        self.keys.decrypt_ciphertext(&parsed)
    }

    /// Authenticate, check for replay, then decrypt one packet into a
    /// caller-owned plaintext buffer.
    pub fn decrypt_into<'a>(
        &mut self,
        packet: &[u8],
        output: &'a mut [u8],
    ) -> Result<DecryptedPacketView<'a>, EspError> {
        let parsed = ParsedEsp::parse(packet, self.keys.authentication.icv_len())?;
        self.keys.verify_icv(parsed.authenticated, parsed.icv)?;
        self.replay.check_and_update(u64::from(parsed.sequence))?;
        self.keys.decrypt_ciphertext_into(&parsed, output)
    }

    /// Reset the replay window, for example after a rekey.
    pub fn reset_replay(&mut self) {
        self.replay.reset();
    }
}

/// Keepalive state without timers or I/O.
///
/// The caller drives it with a monotonic clock. [`KeepaliveState::due`] is a
/// pure query; it never sleeps or sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveState {
    interval_seconds: u64,
    last_sent_seconds: u64,
    last_received_seconds: u64,
}

impl KeepaliveState {
    /// Create state with the given interval in seconds.
    pub const fn new(interval_seconds: u64) -> Self {
        Self {
            interval_seconds,
            last_sent_seconds: 0,
            last_received_seconds: 0,
        }
    }

    /// Whether a keepalive is due at `now_seconds`.
    pub const fn due(&self, now_seconds: u64) -> bool {
        now_seconds.saturating_sub(self.last_sent_seconds) >= self.interval_seconds
    }

    /// Record that a keepalive was sent.
    pub fn record_sent(&mut self, now_seconds: u64) {
        self.last_sent_seconds = now_seconds;
    }

    /// Record that any authenticated packet was received.
    pub fn record_received(&mut self, now_seconds: u64) {
        self.last_received_seconds = now_seconds;
    }

    /// Seconds since the last authenticated receive.
    pub const fn since_received(&self, now_seconds: u64) -> u64 {
        now_seconds.saturating_sub(self.last_received_seconds)
    }

    /// Configured interval in seconds.
    pub const fn interval_seconds(&self) -> u64 {
        self.interval_seconds
    }
}

/// Build the ESP keepalive packet for `sa`.
///
/// The keepalive carries a **single 0x00 byte** as the inner payload with next
/// header [`NEXT_HEADER_IPV4`]. The reference builds its probe packet exactly
/// that way (`pkt->len = 1; pkt->data[0] = 0;`), and it recognises a received
/// probe by the same shape. An empty payload is not the same thing: a peer that
/// treats zero-length inner payloads as malformed sees no traffic at all, so the
/// SA goes idle and the tunnel is torn down.
pub fn keepalive_packet(sa: &mut OutboundSa) -> Result<Vec<u8>, EspError> {
    sa.encrypt(&[0u8], NEXT_HEADER_IPV4)
}

/// Why a rekey is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyReason {
    /// The time lifetime is within its margin.
    LifetimeSeconds,
    /// The byte lifetime is within its margin.
    LifetimeBytes,
}

/// Rekey policy as a pure decision function.
///
/// Lifetimes normally come from KMP 301 group 8 attributes 5 and 6. The observed
/// handshake did not record either value, so this type does not invent defaults: the caller
/// supplies the policy. [`RekeyPolicy::from_esp_proposal`] treats a zero
/// lifetime as "no limit", which is an inference, not observed behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyPolicy {
    /// Soft lifetime in seconds, or `None` for no limit.
    pub lifetime_seconds: Option<u64>,
    /// Soft lifetime in bytes, or `None` for no limit.
    pub lifetime_bytes: Option<u64>,
    /// Rekey this many seconds before `lifetime_seconds`.
    pub margin_seconds: u64,
    /// Rekey this many bytes before `lifetime_bytes`.
    pub margin_bytes: u64,
}

impl RekeyPolicy {
    /// Build a policy from explicit limits and margins.
    pub const fn new(
        lifetime_seconds: Option<u64>,
        lifetime_bytes: Option<u64>,
        margin_seconds: u64,
        margin_bytes: u64,
    ) -> Self {
        Self {
            lifetime_seconds,
            lifetime_bytes,
            margin_seconds,
            margin_bytes,
        }
    }

    /// Build a policy from the gateway's ESP proposal.
    pub fn from_esp_proposal(
        proposal: &EspProposal,
        margin_seconds: u64,
        margin_bytes: u64,
    ) -> Self {
        Self {
            lifetime_seconds: proposal
                .lifetime_seconds
                .map(u64::from)
                .filter(|value| *value != 0),
            lifetime_bytes: proposal
                .lifetime_bytes
                .map(u64::from)
                .filter(|value| *value != 0),
            margin_seconds,
            margin_bytes,
        }
    }

    /// Whether a rekey is due at the supplied counters.
    ///
    /// `bytes_sent + bytes_received` is compared with the byte lifetime; the
    /// elapsed time is compared with the time lifetime. Saturating arithmetic
    /// avoids overflow if a counter is near `u64::MAX`.
    pub fn due(
        &self,
        elapsed_seconds: u64,
        bytes_sent: u64,
        bytes_received: u64,
    ) -> Option<RekeyReason> {
        if let Some(lifetime) = self.lifetime_seconds {
            if elapsed_seconds.saturating_add(self.margin_seconds) >= lifetime {
                return Some(RekeyReason::LifetimeSeconds);
            }
        }
        if let Some(lifetime) = self.lifetime_bytes {
            let total = bytes_sent.saturating_add(bytes_received);
            if total.saturating_add(self.margin_bytes) >= lifetime {
                return Some(RekeyReason::LifetimeBytes);
            }
        }
        None
    }
}

/// The UDP side of an ESP session.
///
/// Tests provide an in-memory implementation; [`UdpEspTransport`] is the real
/// socket. A `recv` that has nothing to return reports `WouldBlock` or
/// `TimedOut`, which the session treats as "no packet right now".
pub trait EspUdp {
    /// Send one complete ESP packet.
    fn send(&mut self, packet: &[u8]) -> io::Result<usize>;
    /// Receive one packet, or an error of kind `WouldBlock`/`TimedOut`.
    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
    /// A raw platform handle that becomes readable when a datagram arrives.
    ///
    /// The live socket returns its OS handle; in-memory test transports keep
    /// the default and the caller falls back to a bounded sleep.
    fn wait_handle(&self) -> Option<isize> {
        None
    }
}

/// The tunnel-device side of an ESP session.
///
/// `recv` returns `Ok(None)` when no packet is ready. The real adapter maps the
/// platform device's timeout to that value.
pub trait EspDevice {
    /// Receive one inner IP packet, or `None` when none is ready.
    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>>;
    /// Deliver one decrypted inner IP packet.
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;
    /// A raw platform handle that becomes readable when a packet is waiting.
    ///
    /// Wintun returns its read-wait event; in-memory test devices keep the
    /// default and the caller falls back to a bounded sleep.
    fn wait_handle(&self) -> Option<isize> {
        None
    }
}

/// A connected UDP socket for ESP.
///
/// The socket binds the wildcard address in the peer's family and lets the OS
/// choose the local port, then connects it to the gateway so `send` does not
/// need a destination each time.
pub struct UdpEspTransport {
    socket: UdpSocket,
}

impl UdpEspTransport {
    /// Create the transport.
    ///
    /// `peer` is the TLS peer address. `port` should be the ESP UDP port from
    /// KMP 301 group 8 attr 4 (typically 4500). The socket is
    /// non-blocking: an empty socket reports `WouldBlock` immediately instead
    /// of waiting for a read timeout.
    pub fn connect(peer: SocketAddr, port: u16) -> io::Result<Self> {
        let bind: SocketAddr = if peer.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(SocketAddr::new(peer.ip(), port))?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }

    /// The local address the OS chose.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The connected gateway address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }
}

impl fmt::Debug for UdpEspTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpEspTransport")
            .field("local_addr", &self.local_addr().ok())
            .field("peer_addr", &self.peer_addr().ok())
            .finish()
    }
}

impl EspUdp for UdpEspTransport {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.socket.send(packet)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buffer)
    }

    fn wait_handle(&self) -> Option<isize> {
        raw_socket_handle(&self.socket)
    }
}

#[cfg(windows)]
fn raw_socket_handle(socket: &UdpSocket) -> Option<isize> {
    use std::os::windows::io::AsRawSocket;
    Some(socket.as_raw_socket() as isize)
}

#[cfg(unix)]
fn raw_socket_handle(socket: &UdpSocket) -> Option<isize> {
    use std::os::unix::io::AsRawFd;
    Some(socket.as_raw_fd() as isize)
}

#[cfg(not(any(windows, unix)))]
fn raw_socket_handle(_socket: &UdpSocket) -> Option<isize> {
    None
}

/// The two directions of an ESP session.
///
/// `outbound_*` is the gateway's KMP 301 group 7 material (used to encrypt our
/// packets); `inbound_*` is the client material generated for KMP 302 (used to
/// decrypt the gateway's packets).
#[derive(Clone)]
pub struct EspSessionMaterial {
    /// SPI written to outbound packets, from KMP 301 group 7 attr 1.
    pub outbound_spi: u32,
    /// Keys for outbound packets, from KMP 301 group 7 attr 2.
    pub outbound_keys: EspKeys,
    /// Our SPI sent in KMP 302, expected on inbound packets.
    pub inbound_spi: u32,
    /// Keys for inbound packets, generated for KMP 302.
    pub inbound_keys: EspKeys,
}

impl fmt::Debug for EspSessionMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspSessionMaterial")
            .field("outbound_spi", &format_args!("{:#010x}", self.outbound_spi))
            .field("inbound_spi", &format_args!("{:#010x}", self.inbound_spi))
            .field("outbound_keys", &self.outbound_keys)
            .field("inbound_keys", &self.inbound_keys)
            .finish()
    }
}

/// One KMP message read from the retained control channel.
///
/// The complete framed record is retained so a gateway-initiated KMP 302 can be
/// parsed. The record may contain live key material: `Debug` prints framing
/// facts only, and callers must never log or serialise [`ReceivedKmp::record`].
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedKmp {
    /// KMP message number (302 negotiation, 303 client configuration, ...).
    pub number: u16,
    /// Declared TLS-record length, excluding the two-byte prefix.
    pub record_length: usize,
    /// Payload length after the 20-byte KMP header.
    pub payload_len: usize,
    /// Complete framed record: two-byte length prefix, 20-byte KMP header and
    /// payload. This may contain key material; never log or serialise it.
    pub record: Vec<u8>,
}

impl fmt::Debug for ReceivedKmp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedKmp")
            .field("number", &self.number)
            .field("record_length", &self.record_length)
            .field("payload_len", &self.payload_len)
            .field("record", &format_args!("<redacted>"))
            .finish()
    }
}

/// One message channel to the oNCP control plane.
///
/// The live implementation is the retained [`crate::oncp::LiveHandshake`]: a
/// rekey writes one KMP record on the same TLS stream that carried KMP 301 and
/// polls the same stream for the reply.
pub trait KmpChannel {
    /// Write one complete, already-framed KMP message.
    fn send_kmp(&mut self, message: &[u8]) -> io::Result<()>;

    /// Read one pending KMP message without waiting for a full round trip.
    ///
    /// `Ok(None)` means no message is available yet. Implementations without a
    /// readable channel may keep this default. The returned record is used both
    /// to confirm a client-initiated rekey and to apply a gateway-initiated
    /// KMP 302.
    fn recv_kmp(&mut self) -> io::Result<Option<ReceivedKmp>> {
        Ok(None)
    }
}

/// Keepalive, peer timeout and rekey settings for an [`EspSession`].
#[derive(Debug, Clone, Copy)]
pub struct EspSessionConfig {
    /// Keepalive interval in seconds.
    pub keepalive_interval_seconds: u64,
    /// Silence after which the peer is considered unresponsive.
    pub peer_timeout: Duration,
    /// When a rekey becomes due.
    pub rekey_policy: RekeyPolicy,
    /// How long the previous inbound SPI stays acceptable after a rekey.
    ///
    /// The same window bounds how long an unconfirmed attempt waits for a
    /// KMP 303 reply or an inbound packet on the new SPI.
    pub rekey_grace: Duration,
    /// MTU echoed in the KMP 303 reply that follows a rekey KMP 302.
    pub mtu: u16,
}

impl EspSessionConfig {
    /// Settings with rekey disabled, useful for tests and callers without a
    /// KMP channel.
    pub const fn without_rekey(
        keepalive_interval_seconds: u64,
        peer_timeout: Duration,
        mtu: u16,
    ) -> Self {
        Self {
            keepalive_interval_seconds,
            peer_timeout,
            rekey_policy: RekeyPolicy::new(None, None, 0, 0),
            rekey_grace: Duration::ZERO,
            mtu,
        }
    }
}

/// The previous inbound SA, still accepted until `expires_at`.
struct RetiringInbound {
    spi: u32,
    sa: InboundSa,
    expires_at: Instant,
}

/// A gateway-initiated exchange we answered, awaiting the peer's switch.
///
/// While this is set another inbound KMP 302 still has its outbound keys
/// applied, but does not start a second proposal. It is cleared when an
/// authenticated packet arrives on the new inbound SPI or when the grace
/// window expires.
struct ServerReply {
    inbound_spi: u32,
    expires_at: Instant,
}

/// A rekey whose new keys have not been confirmed by the peer.
///
/// The inbound SA is installed immediately so a packet using the new SPI can be
/// decrypted, but the outbound SA stays on the old keys until confirmation.
struct PendingRekey {
    inbound_spi: u32,
    inbound: InboundSa,
    /// Outbound keys to install on confirmation. `None` means a gateway-driven
    /// 302 supplied the outbound SA after this attempt started, so confirmation
    /// must not overwrite it.
    outbound_keys: Option<EspKeys>,
    outbound_iv: [u8; ESP_IV_LEN],
    started_at: Instant,
    expires_at: Instant,
    sent_302_len: usize,
    sent_303_len: usize,
    received: Option<ReceivedKmp>,
    channel_failed: bool,
}

/// How long an unconfirmed attempt waits before the first retry.
const REKEY_RETRY_INITIAL: Duration = Duration::from_secs(60);
/// Backoff after a retry also fails to confirm.
const REKEY_RETRY_MAX: Duration = Duration::from_secs(300);
/// How often the live loop polls the retained oNCP channel when idle.
const KMP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Which signal proved the peer accepted the new keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RekeyConfirmation {
    Kmp303,
    InboundSpi,
}

impl RekeyConfirmation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Kmp303 => "KMP 303 reply",
            Self::InboundSpi => "inbound packet on the new SPI",
        }
    }
}

/// Live ESP data plane: one outbound SA, one inbound SA and a replay window.
///
/// The session owns no sockets or devices; [`EspSession::poll_once`] takes them
/// as arguments so tests can use an in-memory loopback. It also owns the
/// reusable packet buffers, so a steady-state packet does not allocate.
/// Malformed or unauthenticated packets are logged at debug level and dropped;
/// they never panic and never reach the device.
pub struct EspSession {
    outbound: OutboundSa,
    inbound: InboundSa,
    inbound_spi: u32,
    retiring_inbound: Option<RetiringInbound>,
    pending_rekey: Option<PendingRekey>,
    server_reply: Option<ServerReply>,
    rekey_retry_at: Option<Instant>,
    rekey_backoff: Duration,
    kmp: Option<Box<dyn KmpChannel>>,
    next_kmp_poll: Instant,
    keepalive: KeepaliveState,
    started: Instant,
    last_received: Instant,
    peer_timeout: Duration,
    bytes_sent: u64,
    bytes_received: u64,
    lifetime_started: Instant,
    lifetime_bytes_sent: u64,
    lifetime_bytes_received: u64,
    rekey_policy: RekeyPolicy,
    rekey_grace: Duration,
    mtu: u16,
    udp_buffer: Vec<u8>,
    device_buffer: Vec<u8>,
    plaintext_buffer: Vec<u8>,
    encrypt_buffer: Vec<u8>,
}

impl fmt::Debug for EspSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspSession")
            .field("outbound", &self.outbound)
            .field("inbound", &self.inbound)
            .field("inbound_spi", &format_args!("{:#010x}", self.inbound_spi))
            .field("rekey_in_flight", &self.rekey_in_flight())
            .field(
                "server_reply_in_flight",
                &self.server_reply.as_ref().map(|reply| reply.inbound_spi),
            )
            .field("rekey_retry_at", &self.rekey_retry_at)
            .field("peer_timeout", &self.peer_timeout)
            .field("bytes_sent", &self.bytes_sent)
            .field("bytes_received", &self.bytes_received)
            .finish()
    }
}

impl EspSession {
    /// Build a session. `initial_iv` seeds the outbound CBC chain.
    pub fn new(
        material: EspSessionMaterial,
        initial_iv: [u8; ESP_IV_LEN],
        config: EspSessionConfig,
        now: Instant,
    ) -> Self {
        // Size the device buffer from the negotiated MTU instead of a fixed
        // guess. The UDP side keeps the maximum datagram size because a peer
        // may send a full ESP packet before the tunnel MTU is applied.
        let device_capacity = if config.mtu == 0 {
            1500
        } else {
            usize::from(config.mtu).max(576)
        };
        let wire_capacity = (device_capacity + ESP_WIRE_OVERHEAD).max(2048);

        Self {
            outbound: OutboundSa::new(material.outbound_spi, material.outbound_keys, initial_iv),
            inbound: InboundSa::new(material.inbound_keys),
            inbound_spi: material.inbound_spi,
            retiring_inbound: None,
            pending_rekey: None,
            server_reply: None,
            rekey_retry_at: None,
            rekey_backoff: REKEY_RETRY_INITIAL,
            kmp: None,
            next_kmp_poll: now,
            keepalive: KeepaliveState::new(config.keepalive_interval_seconds),
            started: now,
            last_received: now,
            peer_timeout: config.peer_timeout,
            bytes_sent: 0,
            bytes_received: 0,
            lifetime_started: now,
            lifetime_bytes_sent: 0,
            lifetime_bytes_received: 0,
            rekey_policy: config.rekey_policy,
            rekey_grace: config.rekey_grace,
            mtu: config.mtu,
            udp_buffer: vec![0u8; ESP_MAX_DATAGRAM],
            device_buffer: vec![0u8; device_capacity],
            plaintext_buffer: vec![0u8; ESP_MAX_DATAGRAM],
            encrypt_buffer: vec![0u8; wire_capacity],
        }
    }

    /// Attach the retained oNCP control channel used to send a rekey KMP 302.
    pub fn set_kmp_channel(&mut self, channel: Box<dyn KmpChannel>) {
        self.kmp = Some(channel);
    }

    /// Whether a rekey attempt is waiting for the peer to confirm the new keys.
    ///
    /// The previous inbound SA may still be in its grace window after this
    /// becomes false; the two conditions are deliberately separate.
    pub const fn rekey_in_flight(&self) -> bool {
        self.pending_rekey.is_some()
    }

    /// The configured rekey policy.
    pub const fn rekey_policy(&self) -> RekeyPolicy {
        self.rekey_policy
    }

    /// Our inbound SPI.
    pub const fn inbound_spi(&self) -> u32 {
        self.inbound_spi
    }

    /// The outbound SA.
    pub const fn outbound(&self) -> &OutboundSa {
        &self.outbound
    }

    /// The inbound SA.
    pub const fn inbound(&self) -> &InboundSa {
        &self.inbound
    }

    /// Total bytes sent, including keepalives.
    pub const fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Total authenticated bytes received.
    pub const fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// One non-blocking step: drain every queued datagram, send a keepalive
    /// when due, then drain every queued device packet. Each direction is
    /// capped at [`ESP_BATCH_MAX`]. Returns whether anything happened.
    pub fn poll_once<U: EspUdp, D: EspDevice>(
        &mut self,
        udp: &mut U,
        device: &mut D,
        now: Instant,
    ) -> Result<bool, EspSessionError> {
        if now.duration_since(self.last_received) >= self.peer_timeout {
            return Err(EspSessionError::PeerUnresponsive(self.peer_timeout));
        }

        self.expire_retired(now);
        self.expire_pending_rekey(now);
        self.expire_server_reply(now);

        let mut worked = false;

        // The gateway can send its own KMP 302 at any time. Poll the retained
        // channel on a bounded cadence, and always before deciding that a
        // client-initiated rekey is due, so a queued gateway 302 is applied
        // first and resets the local timer.
        let rekey_due = self.rekey_due(now);
        if self.kmp.is_some()
            && (self.pending_rekey.is_some() || rekey_due.is_some() || now >= self.next_kmp_poll)
        {
            self.poll_kmp(now);
            self.next_kmp_poll = now + KMP_POLL_INTERVAL;
        }

        // Drain every datagram already queued before touching the device. A
        // non-blocking socket reports `WouldBlock` when empty, so this never
        // waits for the next datagram.
        let mut received = 0usize;
        loop {
            let mut buffer = std::mem::take(&mut self.udp_buffer);
            let result = udp.recv(&mut buffer);
            match result {
                Ok(0) => {
                    self.udp_buffer = buffer;
                    break;
                }
                Ok(length) => {
                    let inbound = self.handle_inbound(&buffer[..length], device, now);
                    self.udp_buffer = buffer;
                    inbound?;
                    worked = true;
                    received += 1;
                    if received >= ESP_BATCH_MAX {
                        break;
                    }
                }
                Err(error) if transient(&error) => {
                    self.udp_buffer = buffer;
                    break;
                }
                Err(error) => {
                    self.udp_buffer = buffer;
                    return Err(EspSessionError::Io(error));
                }
            }
        }

        let elapsed_seconds = now.duration_since(self.started).as_secs();
        let retry_ready = self.rekey_retry_at.is_none_or(|at| now >= at);
        if !self.rekey_in_flight() && retry_ready && self.rekey_due(now).is_some() {
            self.begin_rekey(now);
            worked = true;
        }

        if self.keepalive.due(elapsed_seconds) {
            let length =
                self.outbound
                    .encrypt_into(&[0u8], NEXT_HEADER_IPV4, &mut self.encrypt_buffer)?;
            match udp.send(&self.encrypt_buffer[..length]) {
                Ok(_) => {
                    self.bytes_sent = self.bytes_sent.saturating_add(length as u64);
                    self.lifetime_bytes_sent =
                        self.lifetime_bytes_sent.saturating_add(length as u64);
                }
                Err(error) if transient(&error) => {
                    tracing::debug!(%error, "ESP keepalive send would block; dropping it");
                }
                Err(error) => return Err(EspSessionError::Io(error)),
            }
            self.keepalive.record_sent(elapsed_seconds);
            worked = true;
        }

        // Drain every queued device packet, up to the batch cap.
        let mut sent = 0usize;
        loop {
            let mut buffer = std::mem::take(&mut self.device_buffer);
            let result = device.recv(&mut buffer);
            match result {
                Ok(None) | Ok(Some(0)) => {
                    self.device_buffer = buffer;
                    break;
                }
                Ok(Some(length)) => {
                    let outcome = self.send_device_packet(&buffer[..length], udp);
                    self.device_buffer = buffer;
                    outcome?;
                    worked = true;
                    sent += 1;
                    if sent >= ESP_BATCH_MAX {
                        break;
                    }
                }
                Err(error) => {
                    self.device_buffer = buffer;
                    return Err(EspSessionError::Device(error.to_string()));
                }
            }
        }

        Ok(worked)
    }

    /// Encrypt one device packet into the reusable send buffer and hand it to
    /// UDP. A non-blocking send that reports `WouldBlock` is dropped, as UDP
    /// permits, rather than ending a working tunnel.
    fn send_device_packet<U: EspUdp>(
        &mut self,
        packet: &[u8],
        udp: &mut U,
    ) -> Result<(), EspSessionError> {
        let Some(next_header) = inner_next_header(packet) else {
            tracing::debug!(
                length = packet.len(),
                "dropping a device packet that is not IPv4 or IPv6"
            );
            return Ok(());
        };
        let length = self
            .outbound
            .encrypt_into(packet, next_header, &mut self.encrypt_buffer)?;
        match udp.send(&self.encrypt_buffer[..length]) {
            Ok(_) => {
                self.bytes_sent = self.bytes_sent.saturating_add(length as u64);
                self.lifetime_bytes_sent = self.lifetime_bytes_sent.saturating_add(length as u64);
            }
            Err(error) if transient(&error) => {
                tracing::debug!(%error, "ESP send would block; dropping the packet");
            }
            Err(error) => return Err(EspSessionError::Io(error)),
        }
        Ok(())
    }

    fn expire_retired(&mut self, now: Instant) {
        if self
            .retiring_inbound
            .as_ref()
            .is_some_and(|retiring| now >= retiring.expires_at)
        {
            self.retiring_inbound = None;
        }
    }

    fn expire_server_reply(&mut self, now: Instant) {
        if self
            .server_reply
            .as_ref()
            .is_some_and(|reply| now >= reply.expires_at)
        {
            self.server_reply = None;
        }
    }

    fn rekey_due(&self, now: Instant) -> Option<RekeyReason> {
        let elapsed_seconds = now.duration_since(self.lifetime_started).as_secs();
        self.rekey_policy.due(
            elapsed_seconds,
            self.lifetime_bytes_sent,
            self.lifetime_bytes_received,
        )
    }

    fn expire_pending_rekey(&mut self, now: Instant) {
        let Some(pending) = self.pending_rekey.as_ref() else {
            return;
        };
        if now < pending.expires_at {
            return;
        }

        let pending = self
            .pending_rekey
            .take()
            .expect("pending rekey was checked");
        let received = pending
            .received
            .map(|message| format!("KMP {} ({} bytes)", message.number, message.record_length))
            .unwrap_or_else(|| "no response".to_owned());
        tracing::warn!(
            sent_302_bytes = pending.sent_302_len,
            sent_303_bytes = pending.sent_303_len,
            received = %received,
            elapsed_seconds = now.duration_since(pending.started_at).as_secs(),
            "ESP rekey was not confirmed; keeping the current SA and scheduling a retry"
        );
        self.schedule_rekey_retry(now);
    }

    fn schedule_rekey_retry(&mut self, now: Instant) {
        self.rekey_retry_at = Some(now + self.rekey_backoff);
        self.rekey_backoff = REKEY_RETRY_MAX;
    }

    fn poll_kmp(&mut self, now: Instant) {
        let Some(mut channel) = self.kmp.take() else {
            return;
        };

        let mut result = Ok(());
        for _ in 0..16 {
            match channel.recv_kmp() {
                Ok(Some(message)) => {
                    tracing::info!(
                        direction = "inbound",
                        message = message.number,
                        bytes = message.record_length,
                        "ESP rekey: KMP message"
                    );
                    self.handle_kmp_message(message, now, &mut *channel);
                }
                Ok(None) => break,
                Err(error) => {
                    result = Err(error);
                    break;
                }
            }
        }
        self.kmp = Some(channel);

        if let Err(error) = result {
            tracing::warn!(
                %error,
                "ESP rekey: the KMP channel could not be read; waiting for an inbound confirmation"
            );
            if let Some(pending) = self.pending_rekey.as_mut() {
                pending.channel_failed = true;
            }
        }
    }

    fn handle_kmp_message(
        &mut self,
        message: ReceivedKmp,
        now: Instant,
        channel: &mut dyn KmpChannel,
    ) {
        match message.number {
            KMP_ESP_NEGOTIATION => self.handle_server_rekey(&message, now, channel),
            KMP_CLIENT_CONFIG => {
                if self.pending_rekey.is_some() {
                    if let Some(pending) = self.pending_rekey.as_mut() {
                        pending.received = Some(message);
                    }
                    self.confirm_rekey(now, RekeyConfirmation::Kmp303);
                } else {
                    tracing::info!(
                        direction = "inbound",
                        message = KMP_CLIENT_CONFIG,
                        bytes = message.record_length,
                        "ESP rekey: ignoring a KMP 303 outside an exchange"
                    );
                }
            }
            other => {
                tracing::info!(
                    direction = "inbound",
                    message = other,
                    bytes = message.record_length,
                    "ESP rekey: ignoring an unexpected KMP message"
                );
            }
        }
    }

    /// Apply a gateway-initiated KMP 302 and answer with fresh inbound keys.
    ///
    /// Group 7 is an instruction for the client's outbound SA, so it takes
    /// effect immediately. No confirmation is awaited for keys the peer itself
    /// supplied. The local rekey timer restarts from `now`; the previous
    /// outbound SA is replaced because the data plane is synchronous and keeps
    /// no packet buffered across a poll.
    fn handle_server_rekey(
        &mut self,
        message: &ReceivedKmp,
        now: Instant,
        channel: &mut dyn KmpChannel,
    ) {
        let current_encryption = self.outbound.keys().encryption();
        let current_authentication = self.outbound.keys().authentication();
        let negotiation =
            match parse_server_rekey(&message.record, current_encryption, current_authentication) {
                Ok(negotiation) => negotiation,
                Err(error) => {
                    tracing::warn!(
                        direction = "inbound",
                        message = message.number,
                        bytes = message.record_length,
                        %error,
                        "ESP server-driven rekey: rejected an invalid KMP 302"
                    );
                    return;
                }
            };

        let new_keys = match EspKeys::new(
            negotiation.encryption,
            negotiation.authentication,
            negotiation.encryption_key.clone(),
            negotiation.hmac_key.clone(),
        ) {
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "ESP server-driven rekey: the supplied key block does not fit the transforms"
                );
                return;
            }
        };

        tracing::info!(
            direction = "inbound",
            message = message.number,
            bytes = message.record_length,
            outbound_spi = format_args!("{:#010x}", negotiation.outbound_spi),
            encryption = %negotiation.encryption,
            authentication = %negotiation.authentication,
            key_block_len = ESP_KEY_BLOCK_LEN,
            lifetime_bytes = ?negotiation.lifetime_bytes,
            lifetime_seconds = ?negotiation.lifetime_seconds,
            "ESP server-driven rekey: peer supplied our outbound SA"
        );

        // The peer dictated these keys, so install them at once. There is no
        // in-flight packet bookkeeping to preserve: the old SA is replaced.
        let previous_spi = self.outbound.spi();
        self.outbound = OutboundSa::new(negotiation.outbound_spi, new_keys, esp_initial_iv());
        tracing::info!(
            outbound_spi = format_args!("{:#010x}", self.outbound.spi()),
            previous_spi = format_args!("{previous_spi:#010x}"),
            "ESP server-driven rekey: the peer's outbound SA is active"
        );

        if let Some(bytes) = negotiation.lifetime_bytes {
            self.rekey_policy.lifetime_bytes = Some(u64::from(bytes)).filter(|value| *value != 0);
        }
        if let Some(seconds) = negotiation.lifetime_seconds {
            let lifetime = Some(u64::from(seconds)).filter(|value| *value != 0);
            self.rekey_policy.lifetime_seconds = lifetime;
            self.rekey_policy.margin_seconds =
                lifetime.map_or(0, |value| value.saturating_mul(20) / 100);
        }
        self.lifetime_started = now;
        self.lifetime_bytes_sent = 0;
        self.lifetime_bytes_received = 0;
        self.rekey_retry_at = None;
        self.rekey_backoff = REKEY_RETRY_INITIAL;

        if let Some(pending) = self.pending_rekey.as_mut() {
            // Our own proposal is already in flight. Keep its inbound keys and
            // confirmation path, but never let confirmation overwrite the
            // peer-supplied outbound SA.
            pending.outbound_keys = None;
            tracing::info!(
                "ESP server-driven rekey: applied the peer's keys during an exchange in flight; \
                 not starting a second proposal"
            );
            return;
        }
        if self.server_reply.is_some() {
            tracing::info!(
                "ESP server-driven rekey: applied the peer's keys during an exchange in flight; \
                 not starting a second proposal"
            );
            return;
        }

        self.send_server_reply(now, channel);
    }

    /// Send our own KMP 302/303 after the peer dictated the outbound keys.
    ///
    /// The new inbound SA becomes current immediately and the previous inbound
    /// SA stays acceptable for the grace window while the peer switches.
    fn send_server_reply(&mut self, now: Instant, channel: &mut dyn KmpChannel) {
        let encryption = self.outbound.keys().encryption();
        let authentication = self.outbound.keys().authentication();
        let local = EspLocalKeys::generate(encryption, authentication);
        let inbound_keys = match EspKeys::new(
            local.encryption(),
            local.authentication(),
            local.encryption_key().clone(),
            local.hmac_key().clone(),
        ) {
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "ESP server-driven rekey: could not build our inbound SA; keeping the current one"
                );
                return;
            }
        };

        let negotiation = esp_negotiation(&local);
        let config_reply = client_config_reply(self.mtu);
        let result = channel
            .send_kmp(&negotiation)
            .map_err(|source| EspSessionError::Rekey {
                stage: "KMP 302 reply",
                source,
            })
            .and_then(|()| {
                tracing::info!(
                    direction = "outbound",
                    message = 302,
                    bytes = negotiation.len(),
                    "ESP server-driven rekey: KMP message"
                );
                channel
                    .send_kmp(&config_reply)
                    .map_err(|source| EspSessionError::Rekey {
                        stage: "KMP 303 reply",
                        source,
                    })
            })
            .map(|()| {
                tracing::info!(
                    direction = "outbound",
                    message = 303,
                    bytes = config_reply.len(),
                    "ESP server-driven rekey: KMP message"
                );
            });

        match result {
            Ok(()) => {
                let previous_spi = self.inbound_spi;
                let old_inbound =
                    std::mem::replace(&mut self.inbound, InboundSa::new(inbound_keys));
                self.retiring_inbound = Some(RetiringInbound {
                    spi: previous_spi,
                    sa: old_inbound,
                    expires_at: now + self.rekey_grace,
                });
                self.inbound_spi = local.spi();
                self.server_reply = Some(ServerReply {
                    inbound_spi: local.spi(),
                    expires_at: now + self.rekey_grace,
                });
                tracing::info!(
                    inbound_spi = format_args!("{:#010x}", self.inbound_spi),
                    previous_spi = format_args!("{previous_spi:#010x}"),
                    grace_seconds = self.rekey_grace.as_secs(),
                    "ESP server-driven rekey: proposed fresh inbound keys; keeping the previous \
                     inbound SA during the grace window"
                );
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "ESP server-driven rekey: could not send our KMP 302/303; keeping the current \
                     inbound SA"
                );
            }
        }
    }

    /// Switch outbound only after the peer proved it knows the new keys.
    fn confirm_rekey(&mut self, now: Instant, signal: RekeyConfirmation) {
        let Some(pending) = self.pending_rekey.take() else {
            return;
        };
        let received = pending
            .received
            .map(|message| format!("KMP {} ({} bytes)", message.number, message.record_length))
            .unwrap_or_else(|| "none".to_owned());
        tracing::info!(
            confirmation = signal.as_str(),
            received = %received,
            "ESP rekey confirmed; switching the outbound SA"
        );

        let old_inbound = std::mem::replace(&mut self.inbound, pending.inbound);
        self.retiring_inbound = Some(RetiringInbound {
            spi: self.inbound_spi,
            sa: old_inbound,
            expires_at: now + self.rekey_grace,
        });
        self.inbound_spi = pending.inbound_spi;

        if let Some(outbound_keys) = pending.outbound_keys {
            let outbound_spi = self.outbound.spi();
            self.outbound = OutboundSa::new(outbound_spi, outbound_keys, pending.outbound_iv);
        } else {
            tracing::info!(
                outbound_spi = format_args!("{:#010x}", self.outbound.spi()),
                "ESP rekey confirmed; keeping the peer-supplied outbound SA"
            );
        }
        self.lifetime_started = now;
        self.lifetime_bytes_sent = 0;
        self.lifetime_bytes_received = 0;
        self.rekey_retry_at = None;
        self.rekey_backoff = REKEY_RETRY_INITIAL;
    }

    /// Discard any KMP message already queued before a new attempt starts.
    fn drain_kmp(&mut self, channel: &mut dyn KmpChannel) {
        for _ in 0..16 {
            match channel.recv_kmp() {
                Ok(Some(message)) => {
                    tracing::info!(
                        direction = "inbound",
                        message = message.number,
                        bytes = message.record_length,
                        "ESP rekey: discarding a stale KMP message before a new attempt"
                    );
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(%error, "ESP rekey: could not drain the KMP channel");
                    break;
                }
            }
        }
    }

    /// Send KMP 302 then KMP 303 and install only the pending inbound SA.
    fn begin_rekey(&mut self, now: Instant) {
        if self.rekey_in_flight() {
            return;
        }

        let Some(mut channel) = self.kmp.take() else {
            tracing::warn!(
                "ESP rekey is due but no oNCP KMP channel is attached; keeping the current SA"
            );
            self.schedule_rekey_retry(now);
            return;
        };

        // A KMP 303 carries no correlation to a particular 302, so a reply that
        // was queued after an earlier abandoned attempt must never be allowed to
        // confirm this one.
        self.drain_kmp(&mut *channel);

        let result = self.send_rekey_and_install(&mut *channel, now);
        self.kmp = Some(channel);

        match result {
            Ok(pending) => {
                tracing::info!(
                    sent_302_bytes = pending.sent_302_len,
                    sent_303_bytes = pending.sent_303_len,
                    retry_seconds = self.rekey_grace.as_secs(),
                    "ESP rekey sent; waiting for confirmation before switching the outbound SA"
                );
                self.pending_rekey = Some(pending);
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "ESP rekey could not be sent; keeping the current SA and scheduling a retry"
                );
                self.schedule_rekey_retry(now);
            }
        }
    }

    fn send_rekey_and_install(
        &mut self,
        channel: &mut dyn KmpChannel,
        now: Instant,
    ) -> Result<PendingRekey, EspSessionError> {
        let encryption = self.outbound.keys().encryption();
        let authentication = self.outbound.keys().authentication();
        let (local, initial_iv) = EspLocalKeys::generate_with_iv(encryption, authentication);

        let negotiation = esp_negotiation(&local);
        channel
            .send_kmp(&negotiation)
            .map_err(|source| EspSessionError::Rekey {
                stage: "KMP 302",
                source,
            })?;
        tracing::info!(
            direction = "outbound",
            message = 302,
            bytes = negotiation.len(),
            "ESP rekey: KMP message"
        );

        let config_reply = client_config_reply(self.mtu);
        channel
            .send_kmp(&config_reply)
            .map_err(|source| EspSessionError::Rekey {
                stage: "KMP 303",
                source,
            })?;
        tracing::info!(
            direction = "outbound",
            message = 303,
            bytes = config_reply.len(),
            "ESP rekey: KMP message"
        );

        let new_keys = EspKeys::new(
            encryption,
            authentication,
            local.encryption_key().clone(),
            local.hmac_key().clone(),
        )
        .map_err(|error| EspSessionError::Rekey {
            stage: "installing new keys",
            source: io::Error::other(error.to_string()),
        })?;

        Ok(PendingRekey {
            inbound_spi: local.spi(),
            inbound: InboundSa::new(new_keys.clone()),
            outbound_keys: Some(new_keys),
            outbound_iv: initial_iv,
            started_at: now,
            expires_at: now + self.rekey_grace,
            sent_302_len: negotiation.len(),
            sent_303_len: config_reply.len(),
            received: None,
            channel_failed: false,
        })
    }

    fn handle_inbound<D: EspDevice>(
        &mut self,
        packet: &[u8],
        device: &mut D,
        now: Instant,
    ) -> Result<(), EspSessionError> {
        let mut plaintext = std::mem::take(&mut self.plaintext_buffer);
        let result = self.handle_inbound_into(packet, device, now, &mut plaintext);
        self.plaintext_buffer = plaintext;
        result
    }

    fn handle_inbound_into<D: EspDevice>(
        &mut self,
        packet: &[u8],
        device: &mut D,
        now: Instant,
        plaintext: &mut [u8],
    ) -> Result<(), EspSessionError> {
        let Some(spi) = peek_spi(packet) else {
            tracing::debug!(length = packet.len(), "dropping a short ESP packet");
            return Ok(());
        };

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Selected {
            Current,
            Pending,
            Retiring,
        }

        let pending_spi = self
            .pending_rekey
            .as_ref()
            .map(|pending| pending.inbound_spi);
        let selected = if spi == self.inbound_spi {
            Some(Selected::Current)
        } else if pending_spi == Some(spi) {
            Some(Selected::Pending)
        } else if self
            .retiring_inbound
            .as_ref()
            .is_some_and(|retiring| retiring.spi == spi && now < retiring.expires_at)
        {
            Some(Selected::Retiring)
        } else {
            None
        };
        let Some(selected) = selected else {
            tracing::debug!(
                spi = format_args!("{spi:#010x}"),
                expected = format_args!("{:#010x}", self.inbound_spi),
                "dropping an ESP packet for an unknown SPI"
            );
            return Ok(());
        };

        // The peer is alive: a packet carrying one of our SPIs arrived. Liveness
        // must not depend on the packet also decrypting — a gateway keepalive
        // that this build cannot authenticate would otherwise age the SA out and
        // tear down a working tunnel.
        self.last_received = now;
        self.keepalive
            .record_received(now.duration_since(self.started).as_secs());

        let decrypted = match selected {
            Selected::Current => self.inbound.decrypt_into(packet, plaintext),
            Selected::Pending => match self.pending_rekey.as_mut() {
                Some(pending) => pending.inbound.decrypt_into(packet, plaintext),
                None => return Ok(()),
            },
            Selected::Retiring => match self.retiring_inbound.as_mut() {
                Some(retiring) => retiring.sa.decrypt_into(packet, plaintext),
                None => return Ok(()),
            },
        };
        let decrypted = match decrypted {
            Ok(decrypted) => decrypted,
            Err(EspError::Replay(error)) => {
                tracing::debug!(%error, "dropping a replayed ESP packet");
                return Ok(());
            }
            Err(error) => {
                tracing::debug!(%error, "dropping an invalid ESP packet");
                return Ok(());
            }
        };

        // An authenticated packet on the new SPI is the data-plane proof that
        // the peer installed the keys we sent in KMP 302.
        if selected == Selected::Pending {
            tracing::info!(
                direction = "inbound",
                spi = format_args!("{spi:#010x}"),
                bytes = packet.len(),
                "ESP rekey: inbound packet on the new SPI"
            );
            self.confirm_rekey(now, RekeyConfirmation::InboundSpi);
        } else if self
            .server_reply
            .as_ref()
            .is_some_and(|reply| reply.inbound_spi == spi)
        {
            tracing::info!(
                direction = "inbound",
                spi = format_args!("{spi:#010x}"),
                bytes = packet.len(),
                "ESP server-driven rekey: peer switched to the proposed inbound SPI"
            );
            self.server_reply = None;
        }

        self.bytes_received = self.bytes_received.saturating_add(packet.len() as u64);
        self.lifetime_bytes_received = self
            .lifetime_bytes_received
            .saturating_add(packet.len() as u64);

        // A one-byte 0x00 inner payload is the peer's keepalive probe, not an IP
        // packet: never hand that to the device.
        if decrypted.payload.len() < MIN_IP_PACKET_LEN {
            tracing::debug!(
                length = decrypted.payload.len(),
                "received an ESP keepalive"
            );
            return Ok(());
        }

        match decrypted.next_header {
            NEXT_HEADER_IPV4 | NEXT_HEADER_IPV6 => {
                device
                    .send(decrypted.payload)
                    .map_err(|error| EspSessionError::Device(error.to_string()))?;
            }
            NEXT_HEADER_LZO_IPV4 => {
                tracing::debug!("dropping an ESP packet with unsupported LZO compression");
            }
            other => {
                tracing::debug!(
                    next_header = other,
                    "dropping an ESP packet with an unknown next header"
                );
            }
        }
        Ok(())
    }
}

fn inner_next_header(packet: &[u8]) -> Option<u8> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Some(NEXT_HEADER_IPV4),
        Some(6) => Some(NEXT_HEADER_IPV6),
        _ => None,
    }
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
    )
}

/// Errors from the live ESP session.
#[derive(Debug, thiserror::Error)]
pub enum EspSessionError {
    /// The gateway stopped sending authenticated packets.
    #[error("ESP peer stopped responding for {0:?}")]
    PeerUnresponsive(Duration),
    /// A socket or device operation failed.
    #[error("ESP session I/O: {0}")]
    Io(#[from] io::Error),
    /// The packet layer rejected an outbound packet.
    #[error("ESP packet: {0}")]
    Packet(#[from] EspError),
    /// The tunnel device failed.
    #[error("ESP tunnel device: {0}")]
    Device(String),
    /// A rekey could not be sent or installed; the tunnel must end rather than
    /// keep using an expired SA.
    #[error("ESP rekey failed during {stage}: {source}")]
    Rekey {
        /// Step that failed.
        stage: &'static str,
        /// Underlying I/O or key error.
        #[source]
        source: io::Error,
    },
}

/// Errors from the ESP packet layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EspError {
    /// The packet was shorter than header + one block + ICV.
    #[error("ESP packet is {actual} bytes, need at least {minimum}")]
    PacketTooShort {
        /// Minimum length.
        minimum: usize,
        /// Observed length.
        actual: usize,
    },
    /// The ciphertext was empty or not a multiple of the AES block size.
    #[error("ESP ciphertext length {actual} is not a positive multiple of 16")]
    InvalidCiphertextLength {
        /// Observed ciphertext length.
        actual: usize,
    },
    /// The ICV length did not match the transform.
    #[error("ESP ICV is {actual} bytes, expected {expected}")]
    IcvLength {
        /// Expected length.
        expected: usize,
        /// Observed length.
        actual: usize,
    },
    /// The truncated HMAC did not verify.
    #[error("ESP authentication failed")]
    AuthenticationFailed,
    /// The pad-length byte pointed outside the plaintext.
    #[error("ESP padding is invalid")]
    InvalidPadding,
    /// A key had the wrong length for its transform.
    #[error("{algorithm} key is {actual} bytes, expected {expected}")]
    KeyLength {
        /// Transform name.
        algorithm: &'static str,
        /// Required length.
        expected: usize,
        /// Observed length.
        actual: usize,
    },
    /// The key block was shorter than the transforms need.
    #[error("ESP key block is {actual} bytes, need {needed}")]
    KeyBlockTooShort {
        /// Bytes required.
        needed: usize,
        /// Bytes observed.
        actual: usize,
    },
    /// The send sequence number reached `u32::MAX` and was used.
    #[error("ESP sequence number exhausted; refusing to wrap")]
    SequenceExhausted,
    /// The replay window rejected the packet.
    #[error("ESP replay check failed: {0}")]
    Replay(#[from] ReplayError),
    /// The AES backend rejected the key, IV or buffer.
    #[error("ESP cipher failure: {0}")]
    Cipher(&'static str),
    /// A caller-supplied output buffer could not hold the result.
    #[error("ESP output buffer is {available} bytes, need {needed}")]
    OutputBufferTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
}

struct ParsedEsp<'a> {
    spi: u32,
    sequence: u32,
    iv: [u8; ESP_IV_LEN],
    ciphertext: &'a [u8],
    icv: &'a [u8],
    authenticated: &'a [u8],
}

impl<'a> ParsedEsp<'a> {
    fn parse(packet: &'a [u8], icv_len: usize) -> Result<Self, EspError> {
        let minimum = ESP_HEADER_LEN + ESP_IV_LEN + icv_len;
        if packet.len() < minimum {
            return Err(EspError::PacketTooShort {
                minimum,
                actual: packet.len(),
            });
        }

        let body_end = packet.len() - icv_len;
        let ciphertext = &packet[ESP_HEADER_LEN..body_end];
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(ESP_IV_LEN) {
            return Err(EspError::InvalidCiphertextLength {
                actual: ciphertext.len(),
            });
        }

        let mut iv = [0u8; ESP_IV_LEN];
        iv.copy_from_slice(&packet[8..ESP_HEADER_LEN]);

        Ok(Self {
            spi: u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]),
            sequence: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
            iv,
            ciphertext,
            icv: &packet[body_end..],
            authenticated: &packet[..body_end],
        })
    }
}

fn padding_len(payload_len: usize) -> usize {
    (ESP_IV_LEN - ((payload_len + 2) % ESP_IV_LEN)) % ESP_IV_LEN
}

fn aes_cbc_encrypt(
    encryption: EspEncryption,
    key: &[u8],
    iv: &[u8; ESP_IV_LEN],
    data: &mut [u8],
) -> Result<(), EspError> {
    if data.is_empty() || !data.len().is_multiple_of(ESP_IV_LEN) {
        return Err(EspError::InvalidCiphertextLength { actual: data.len() });
    }
    match encryption {
        EspEncryption::Aes128Cbc => {
            let cipher = Encryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|_| EspError::Cipher("invalid AES-128 key or IV"))?;
            cipher
                .encrypt_padded_mut::<NoPadding>(data, data.len())
                .map_err(|_| EspError::Cipher("AES-128-CBC encryption failed"))?;
        }
        EspEncryption::Aes256Cbc => {
            let cipher = Encryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| EspError::Cipher("invalid AES-256 key or IV"))?;
            cipher
                .encrypt_padded_mut::<NoPadding>(data, data.len())
                .map_err(|_| EspError::Cipher("AES-256-CBC encryption failed"))?;
        }
    }
    Ok(())
}

fn aes_cbc_decrypt(
    encryption: EspEncryption,
    key: &[u8],
    iv: &[u8; ESP_IV_LEN],
    data: &mut [u8],
) -> Result<(), EspError> {
    if data.is_empty() || !data.len().is_multiple_of(ESP_IV_LEN) {
        return Err(EspError::InvalidCiphertextLength { actual: data.len() });
    }
    match encryption {
        EspEncryption::Aes128Cbc => {
            let cipher = Decryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|_| EspError::Cipher("invalid AES-128 key or IV"))?;
            cipher
                .decrypt_padded_mut::<NoPadding>(data)
                .map_err(|_| EspError::Cipher("AES-128-CBC decryption failed"))?;
        }
        EspEncryption::Aes256Cbc => {
            let cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| EspError::Cipher("invalid AES-256 key or IV"))?;
            cipher
                .decrypt_padded_mut::<NoPadding>(data)
                .map_err(|_| EspError::Cipher("AES-256-CBC decryption failed"))?;
        }
    }
    Ok(())
}

fn hmac_into(
    authentication: EspAuthentication,
    key: &[u8],
    data: &[u8],
    output: &mut [u8; MAX_ICV_LEN],
) -> Result<usize, EspError> {
    match authentication {
        EspAuthentication::HmacMd5 => {
            let mut mac = Hmac::<Md5>::new_from_slice(key).map_err(|_| EspError::KeyLength {
                algorithm: authentication.as_str(),
                expected: authentication.key_len(),
                actual: key.len(),
            })?;
            mac.update(data);
            let digest = mac.finalize().into_bytes();
            output[..digest.len()].copy_from_slice(&digest);
            Ok(digest.len())
        }
        EspAuthentication::HmacSha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| EspError::KeyLength {
                algorithm: authentication.as_str(),
                expected: authentication.key_len(),
                actual: key.len(),
            })?;
            mac.update(data);
            let digest = mac.finalize().into_bytes();
            output[..digest.len()].copy_from_slice(&digest);
            Ok(digest.len())
        }
    }
}

#[cfg(test)]
fn hmac_digest(
    authentication: EspAuthentication,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, EspError> {
    let mut output = [0u8; MAX_ICV_LEN];
    let length = hmac_into(authentication, key, data, &mut output)?;
    Ok(output[..length].to_vec())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use crate::oncp::parse_esp_negotiation;

    // All vectors below are derived from published standards unless a test is
    // explicitly labelled "round-trip only".

    fn hex(bytes: &str) -> Vec<u8> {
        if bytes.contains(' ') {
            bytes
                .split_whitespace()
                .map(|part| u8::from_str_radix(part, 16).expect("hex"))
                .collect()
        } else {
            assert_eq!(bytes.len() % 2, 0, "hex string has an odd length");
            (0..bytes.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&bytes[index..index + 2], 16).expect("hex"))
                .collect()
        }
    }

    fn keys(encryption: EspEncryption, authentication: EspAuthentication, seed: u8) -> EspKeys {
        let enc_key = vec![seed; encryption.key_len()];
        let hmac_key = vec![seed.wrapping_add(1); authentication.key_len()];
        EspKeys::new(
            encryption,
            authentication,
            SecretKey::new(enc_key),
            SecretKey::new(hmac_key),
        )
        .expect("keys")
    }

    fn push_attribute(group: &mut Vec<u8>, attr: u16, value: &[u8]) {
        group.extend_from_slice(&attr.to_be_bytes());
        group.extend_from_slice(&(value.len() as u32).to_be_bytes());
        group.extend_from_slice(value);
    }

    fn push_group(payload: &mut Vec<u8>, group: u16, attributes: &[u8]) {
        payload.extend_from_slice(&group.to_be_bytes());
        payload.extend_from_slice(&(attributes.len() as u32).to_be_bytes());
        payload.extend_from_slice(attributes);
    }

    /// Frame a KMP record with the gateway's inbound tag.
    fn kmp_record(number: u16, payload: &[u8]) -> Vec<u8> {
        let record_len = 20 + payload.len();
        let mut out = Vec::with_capacity(2 + record_len);
        out.extend_from_slice(&(record_len as u16).to_le_bytes());
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&number.to_be_bytes());
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn encryption_wire(encryption: EspEncryption) -> u8 {
        match encryption {
            EspEncryption::Aes128Cbc => 0x02,
            EspEncryption::Aes256Cbc => 0x05,
        }
    }

    fn authentication_wire(authentication: EspAuthentication) -> u8 {
        match authentication {
            EspAuthentication::HmacMd5 => 0x01,
            EspAuthentication::HmacSha1 => 0x02,
        }
    }

    fn key_block_fixture() -> Vec<u8> {
        (0..ESP_KEY_BLOCK_LEN)
            .map(|index| 0xa0u8.wrapping_add(index as u8))
            .collect()
    }

    fn keys_from_block(
        block: &[u8],
        encryption: EspEncryption,
        authentication: EspAuthentication,
    ) -> EspKeys {
        let enc_len = encryption.key_len();
        let hmac_len = authentication.key_len();
        EspKeys::new(
            encryption,
            authentication,
            SecretKey::new(block[..enc_len].to_vec()),
            SecretKey::new(block[enc_len..enc_len + hmac_len].to_vec()),
        )
        .expect("keys from block")
    }

    /// Build a gateway-initiated KMP 302 with groups 7 and 8.
    ///
    /// `group8_padding` appends an unknown group 8 attribute whose value is that
    /// many bytes; the 208-byte live fixture uses 36.
    fn server_rekey_302(
        spi: u32,
        encryption: EspEncryption,
        authentication: EspAuthentication,
        key_block: &[u8],
        lifetimes: Option<(u32, u32)>,
        group8_padding: usize,
    ) -> Vec<u8> {
        let mut group7 = Vec::new();
        push_attribute(&mut group7, 1, &spi.to_be_bytes());
        push_attribute(&mut group7, 2, key_block);

        let mut group8 = Vec::new();
        push_attribute(&mut group8, 1, &[encryption_wire(encryption)]);
        push_attribute(&mut group8, 2, &[authentication_wire(authentication)]);
        push_attribute(&mut group8, 4, &4500u16.to_be_bytes());
        if let Some((bytes, seconds)) = lifetimes {
            push_attribute(&mut group8, 5, &bytes.to_be_bytes());
            push_attribute(&mut group8, 6, &seconds.to_be_bytes());
        }
        push_attribute(&mut group8, 10, &1u32.to_be_bytes());
        if group8_padding > 0 {
            push_attribute(&mut group8, 99, &vec![0u8; group8_padding]);
        }

        let mut payload = Vec::new();
        push_group(&mut payload, 7, &group7);
        push_group(&mut payload, 8, &group8);
        kmp_record(crate::ncp::KMP_ESP_NEGOTIATION, &payload)
    }

    // NIST SP 800-38A, F.2.1 CBC-AES128.Encrypt.
    #[test]
    fn nist_sp_800_38a_aes128_cbc_known_answer() {
        let key = hex("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c");
        let iv = hex("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
        let mut block = hex(concat!(
            "6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a ",
            "ae 2d 8a 57 1e 03 ac 9c 9e b7 6f ac 45 af 8e 51 ",
            "30 c8 1c 46 a3 5c e4 11 e5 fb c1 19 1a 0a 52 ef ",
            "f6 9f 24 45 df 4f 9b 17 ad 2b 41 7b e6 6c 37 10",
        ));
        let expected = hex(concat!(
            "76 49 ab ac 81 19 b2 46 ce e9 8e 9b 12 e9 19 7d ",
            "50 86 cb 9b 50 72 19 ee 95 db 11 3a 91 76 78 b2 ",
            "73 be d6 b8 e3 c1 74 3b 71 16 e6 9e 22 22 95 16 ",
            "3f f1 ca a1 68 1f ac 09 12 0e ca 30 75 86 e1 a7",
        ));
        let iv: [u8; 16] = iv.try_into().expect("iv");
        aes_cbc_encrypt(EspEncryption::Aes128Cbc, &key, &iv, &mut block).expect("encrypt");
        assert_eq!(block, expected);

        aes_cbc_decrypt(EspEncryption::Aes128Cbc, &key, &iv, &mut block).expect("decrypt");
        assert_eq!(
            block,
            hex(concat!(
                "6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a ",
                "ae 2d 8a 57 1e 03 ac 9c 9e b7 6f ac 45 af 8e 51 ",
                "30 c8 1c 46 a3 5c e4 11 e5 fb c1 19 1a 0a 52 ef ",
                "f6 9f 24 45 df 4f 9b 17 ad 2b 41 7b e6 6c 37 10",
            ))
        );
    }

    // NIST SP 800-38A, F.2.3 CBC-AES256.Encrypt.
    #[test]
    fn nist_sp_800_38a_aes256_cbc_known_answer() {
        let key = hex(concat!(
            "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 ",
            "1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4",
        ));
        let iv = hex("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
        let plaintext = hex(concat!(
            "6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a ",
            "ae 2d 8a 57 1e 03 ac 9c 9e b7 6f ac 45 af 8e 51 ",
            "30 c8 1c 46 a3 5c e4 11 e5 fb c1 19 1a 0a 52 ef ",
            "f6 9f 24 45 df 4f 9b 17 ad 2b 41 7b e6 6c 37 10",
        ));
        let expected = hex(concat!(
            "f5 8c 4c 04 d6 e5 f1 ba 77 9e ab fb 5f 7b fb d6 ",
            "9c fc 4e 96 7e db 80 8d 67 9f 77 7b c6 70 2c 7d ",
            "39 f2 33 69 a9 d9 ba cf a5 30 e2 63 04 23 14 61 ",
            "b2 eb 05 e2 c3 9b e9 fc da 6c 19 07 8c 6a 9d 1b",
        ));
        let iv: [u8; 16] = iv.try_into().expect("iv");
        let mut block = plaintext.clone();
        aes_cbc_encrypt(EspEncryption::Aes256Cbc, &key, &iv, &mut block).expect("encrypt");
        assert_eq!(block, expected);

        aes_cbc_decrypt(EspEncryption::Aes256Cbc, &key, &iv, &mut block).expect("decrypt");
        assert_eq!(block, plaintext);
    }

    // RFC 2202 test cases 1, 2 and 3 for HMAC-MD5.
    #[test]
    fn rfc_2202_hmac_md5_known_answers() {
        let vectors = [
            (
                vec![0x0b; 16],
                b"Hi There".to_vec(),
                "9294727a3638bb1c13f48ef8158bfc9d",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "750c783e6ab0b503eaa86e310a5db738",
            ),
            (
                vec![0xaa; 16],
                vec![0xdd; 50],
                "56be34521d144c88dbb8c733f0e8b3f6",
            ),
        ];
        for (key, data, expected) in vectors {
            let digest = hmac_digest(EspAuthentication::HmacMd5, &key, &data).expect("hmac");
            assert_eq!(hex(expected), digest);
        }
    }

    // RFC 2202 test cases 1, 2 and 3 for HMAC-SHA1.
    #[test]
    fn rfc_2202_hmac_sha1_known_answers() {
        let vectors = [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b617318655057264e28bc0b6fb378c8ef146be00",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            ),
        ];
        for (key, data, expected) in vectors {
            let digest = hmac_digest(EspAuthentication::HmacSha1, &key, &data).expect("hmac");
            assert_eq!(hex(expected), digest);
        }
    }

    // Round-trip only: no standard vector exists for this exact ESP framing.
    #[test]
    fn esp_round_trip_with_a_fixed_key_and_iv() {
        for (encryption, authentication) in [
            (EspEncryption::Aes128Cbc, EspAuthentication::HmacSha1),
            (EspEncryption::Aes256Cbc, EspAuthentication::HmacMd5),
            (EspEncryption::Aes128Cbc, EspAuthentication::HmacMd5),
            (EspEncryption::Aes256Cbc, EspAuthentication::HmacSha1),
        ] {
            let keys = keys(encryption, authentication, 0x42);
            let mut outbound = OutboundSa::new(0x1a2b_3c4d, keys.clone(), [0x11; 16]);
            let inbound_keys = keys.clone();
            let mut inbound = InboundSa::new(inbound_keys);

            for (index, payload) in [b"".as_slice(), b"hello".as_slice(), &[0x45; 1500]]
                .iter()
                .enumerate()
            {
                let packet = outbound
                    .encrypt(payload, NEXT_HEADER_IPV4)
                    .expect("encrypt");
                assert_eq!(peek_spi(&packet), Some(0x1a2b_3c4d));
                assert_eq!(peek_sequence(&packet), Some(index as u32));
                let decrypted = inbound.decrypt(&packet).expect("decrypt");
                assert_eq!(decrypted.payload, *payload);
                assert_eq!(decrypted.next_header, NEXT_HEADER_IPV4);
                assert_eq!(decrypted.sequence, index as u32);
            }
        }
    }

    #[test]
    fn tampering_with_the_ciphertext_fails_authentication() {
        let keys = keys(EspEncryption::Aes128Cbc, EspAuthentication::HmacSha1, 0x33);
        let mut sa = OutboundSa::new(1, keys.clone(), [0; 16]);
        let mut packet = sa.encrypt(b"payload", NEXT_HEADER_IPV4).expect("encrypt");
        packet[ESP_HEADER_LEN] ^= 0x80;
        assert_eq!(
            keys.decrypt_packet(&packet).expect_err("must fail"),
            EspError::AuthenticationFailed
        );
    }

    #[test]
    fn replay_window_rejects_duplicates_and_too_old_packets() {
        let keys = keys(EspEncryption::Aes128Cbc, EspAuthentication::HmacMd5, 0x44);
        let mut outbound = OutboundSa::new(9, keys.clone(), [0; 16]);
        let first = outbound.encrypt(b"one", NEXT_HEADER_IPV4).expect("one");
        let second = outbound.encrypt(b"two", NEXT_HEADER_IPV4).expect("two");

        let mut inbound = InboundSa::new(keys);
        assert!(inbound.decrypt(&first).is_ok());
        assert!(matches!(
            inbound.decrypt(&first),
            Err(EspError::Replay(ReplayError::Replay { .. }))
        ));
        assert!(inbound.decrypt(&second).is_ok());

        let mut far = OutboundSa::new(9, inbound.keys().clone(), [0; 16]);
        for _ in 0..70 {
            far.encrypt(b"x", NEXT_HEADER_IPV4).expect("advance");
        }
        let too_new = far.encrypt(b"new", NEXT_HEADER_IPV4).expect("new");
        assert!(inbound.decrypt(&too_new).is_ok());
        assert!(matches!(
            inbound.decrypt(&first),
            Err(EspError::Replay(ReplayError::TooOld { .. }))
        ));
    }

    #[test]
    fn sequence_numbers_refuse_to_wrap() {
        let keys = keys(EspEncryption::Aes128Cbc, EspAuthentication::HmacSha1, 0x55);
        let mut sa = OutboundSa::new(1, keys, [0; 16]);
        // Fast-forward without encrypting 4 billion packets.
        sa.next_sequence = u32::MAX;
        assert_eq!(sa.next_sequence(), u32::MAX);
        sa.encrypt(b"last", NEXT_HEADER_IPV4)
            .expect("last sequence");
        assert!(sa.is_exhausted());
        assert_eq!(
            sa.encrypt(b"wrapped", NEXT_HEADER_IPV4)
                .expect_err("must fail"),
            EspError::SequenceExhausted
        );
    }

    #[test]
    fn keepalive_and_rekey_are_pure_decisions() {
        let keys = keys(EspEncryption::Aes128Cbc, EspAuthentication::HmacMd5, 0x66);
        let mut sa = OutboundSa::new(3, keys, [0; 16]);
        let packet = keepalive_packet(&mut sa).expect("keepalive");
        let decrypted = EspKeys::new(
            EspEncryption::Aes128Cbc,
            EspAuthentication::HmacMd5,
            SecretKey::new(vec![0x66; 16]),
            SecretKey::new(vec![0x67; 16]),
        )
        .expect("keys")
        .decrypt_packet(&packet)
        .expect("decrypt keepalive");
        assert_eq!(decrypted.payload, vec![0u8]);
        assert_eq!(decrypted.next_header, NEXT_HEADER_IPV4);

        let mut state = KeepaliveState::new(30);
        assert!(state.due(30));
        state.record_sent(30);
        assert!(!state.due(59));
        assert!(state.due(60));
        state.record_received(70);
        assert_eq!(state.since_received(100), 30);

        let policy = RekeyPolicy::new(Some(3600), Some(1_000_000), 60, 10_000);
        assert_eq!(policy.due(0, 0, 0), None);
        assert_eq!(policy.due(3540, 0, 0), Some(RekeyReason::LifetimeSeconds));
        assert_eq!(
            policy.due(0, 600_000, 390_000),
            Some(RekeyReason::LifetimeBytes)
        );
    }

    #[test]
    fn keys_and_negotiation_render_no_bytes() {
        let keys = keys(EspEncryption::Aes256Cbc, EspAuthentication::HmacSha1, 0x77);
        let debug = format!("{keys:?}");
        assert!(!debug.contains("119, 119"));
        assert!(debug.contains("redacted"));
        assert_eq!(keys.encryption_key_len(), 32);
        assert_eq!(keys.hmac_key_len(), 20);
    }

    #[test]
    fn padding_is_always_a_whole_number_of_blocks() {
        for payload_len in 0..64 {
            let pad = padding_len(payload_len);
            assert!(pad <= 15);
            assert_eq!((payload_len + pad + 2) % 16, 0);
        }
    }

    struct FakeUdp {
        inbound: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
        gateway_keys: EspKeys,
        client_sa: OutboundSa,
        echo: bool,
    }

    impl FakeUdp {
        fn echo(gateway_keys: EspKeys, client_spi: u32, client_keys: EspKeys) -> Self {
            Self {
                inbound: VecDeque::new(),
                sent: Vec::new(),
                gateway_keys,
                client_sa: OutboundSa::new(client_spi, client_keys, [0x33; ESP_IV_LEN]),
                echo: true,
            }
        }

        fn silent(gateway_keys: EspKeys, client_spi: u32, client_keys: EspKeys) -> Self {
            Self {
                echo: false,
                ..Self::echo(gateway_keys, client_spi, client_keys)
            }
        }

        fn inject(&mut self, packet: Vec<u8>) {
            self.inbound.push_back(packet);
        }
    }

    impl EspUdp for FakeUdp {
        fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
            self.sent.push(packet.to_vec());
            if self.echo {
                let decrypted = self
                    .gateway_keys
                    .decrypt_packet(packet)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let reply = self
                    .client_sa
                    .encrypt(&decrypted.payload, decrypted.next_header)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                self.inbound.push_back(reply);
            }
            Ok(packet.len())
        }

        fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.inbound.pop_front() {
                Some(packet) if packet.len() <= buffer.len() => {
                    buffer[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                }
                Some(_) => Err(io::Error::other("fake UDP buffer too small")),
                None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        }
    }

    #[derive(Default)]
    struct FakeDevice {
        outbound: VecDeque<Vec<u8>>,
        inbound: Vec<Vec<u8>>,
    }

    impl EspDevice for FakeDevice {
        fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
            match self.outbound.pop_front() {
                Some(packet) if packet.len() <= buffer.len() => {
                    buffer[..packet.len()].copy_from_slice(&packet);
                    Ok(Some(packet.len()))
                }
                Some(_) => Err(io::Error::other("fake device buffer too small")),
                None => Ok(None),
            }
        }

        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            self.inbound.push(packet.to_vec());
            Ok(())
        }
    }

    /// A 20-byte IPv4 header with a distinctive TTL, so it survives the
    /// minimum-length check that drops keepalive probes.
    fn ipv4_packet(marker: u8) -> Vec<u8> {
        vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x00, marker, 0x0a, 0x00, 0x00, 0x02,
        ]
    }

    fn session_material() -> (EspKeys, EspKeys, EspSessionMaterial) {
        let gateway_keys = keys(EspEncryption::Aes128Cbc, EspAuthentication::HmacSha1, 0x10);
        let client_keys = keys(EspEncryption::Aes128Cbc, EspAuthentication::HmacSha1, 0x20);
        let material = EspSessionMaterial {
            outbound_spi: 0x1111_2222,
            outbound_keys: gateway_keys.clone(),
            inbound_spi: 0x3333_4444,
            inbound_keys: client_keys.clone(),
        };
        (gateway_keys, client_keys, material)
    }

    fn new_session(material: EspSessionMaterial, now: Instant) -> EspSession {
        EspSession::new(
            material,
            [0x5a; ESP_IV_LEN],
            EspSessionConfig {
                keepalive_interval_seconds: 30,
                peer_timeout: Duration::from_secs(90),
                rekey_policy: RekeyPolicy::new(None, None, 0, 0),
                rekey_grace: Duration::from_secs(60),
                mtu: 1396,
            },
            now,
        )
    }

    #[derive(Clone, Default)]
    struct SharedKmp {
        sent: Rc<RefCell<Vec<Vec<u8>>>>,
        incoming: Rc<RefCell<VecDeque<ReceivedKmp>>>,
        fail_at: Option<usize>,
    }

    impl SharedKmp {
        fn with_failure(fail_at: usize) -> Self {
            Self {
                sent: Rc::default(),
                incoming: Rc::default(),
                fail_at: Some(fail_at),
            }
        }

        fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.borrow().clone()
        }

        fn queue_reply(&self, number: u16, record_length: usize) {
            self.incoming.borrow_mut().push_back(ReceivedKmp {
                number,
                record_length,
                payload_len: record_length.saturating_sub(20),
                record: Vec::new(),
            });
        }

        fn queue_message(&self, record: Vec<u8>) {
            let (number, record_length, payload_len) = {
                let frame = crate::oncp::KmpFrame::parse_any(&record).expect("test KMP frame");
                (frame.number, frame.record_length, frame.payload.len())
            };
            self.incoming.borrow_mut().push_back(ReceivedKmp {
                number,
                record_length,
                payload_len,
                record,
            });
        }
    }

    impl KmpChannel for SharedKmp {
        fn send_kmp(&mut self, message: &[u8]) -> io::Result<()> {
            if self.fail_at == Some(self.sent.borrow().len()) {
                self.fail_at = None;
                return Err(io::Error::other("scripted KMP failure"));
            }
            self.sent.borrow_mut().push(message.to_vec());
            Ok(())
        }

        fn recv_kmp(&mut self) -> io::Result<Option<ReceivedKmp>> {
            Ok(self.incoming.borrow_mut().pop_front())
        }
    }

    fn rekey_session(
        material: EspSessionMaterial,
        now: Instant,
        policy: RekeyPolicy,
        grace: Duration,
    ) -> (EspSession, SharedKmp) {
        let mut session = EspSession::new(
            material,
            [0x5a; ESP_IV_LEN],
            EspSessionConfig {
                keepalive_interval_seconds: 100_000,
                peer_timeout: Duration::from_secs(100_000),
                rekey_policy: policy,
                rekey_grace: grace,
                mtu: 1396,
            },
            now,
        );
        let channel = SharedKmp::default();
        session.set_kmp_channel(Box::new(channel.clone()));
        (session, channel)
    }

    fn assert_kmp_numbers(messages: &[Vec<u8>]) {
        assert_eq!(messages.len(), 2, "a rekey sends KMP 302 then KMP 303");
        assert_eq!(
            crate::oncp::KmpFrame::parse_outbound(&messages[0])
                .expect("302")
                .number,
            302
        );
        assert_eq!(
            crate::oncp::KmpFrame::parse_outbound(&messages[1])
                .expect("303")
                .number,
            303
        );
    }

    fn rekey_negotiation(channel: &SharedKmp) -> EspNegotiation {
        let sent = channel.sent();
        parse_esp_negotiation(
            &sent[0],
            EspEncryption::Aes128Cbc,
            EspAuthentication::HmacSha1,
        )
        .expect("new KMP 302")
    }

    #[test]
    fn rekey_trigger_fires_at_eighty_percent_and_not_before() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let old_spi = material.inbound_spi;
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let (mut session, channel) = rekey_session(material, now, policy, Duration::from_secs(60));
        let mut udp = FakeUdp::silent(gateway_keys, old_spi, client_keys);
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(959))
            .expect("not due before 80 percent");
        assert!(channel.sent().is_empty());
        assert!(!session.rekey_in_flight());
        assert_eq!(session.inbound_spi(), old_spi);

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("due at 80 percent");
        assert_kmp_numbers(&channel.sent());
        assert!(session.rekey_in_flight());
        assert_eq!(
            session.inbound_spi(),
            old_spi,
            "the current inbound SPI does not change before confirmation"
        );
        let negotiation = rekey_negotiation(&channel);
        assert_ne!(negotiation.outbound_spi, old_spi);
    }

    #[test]
    fn an_unconfirmed_rekey_keeps_the_old_outbound_sa() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let old_outbound_keys = material.outbound_keys.clone();
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let (mut session, channel) =
            rekey_session(material.clone(), now, policy, Duration::from_secs(30));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        device.outbound.push_back(ipv4_packet(0x40));
        session
            .poll_once(&mut udp, &mut device, now)
            .expect("first packet on the old SA");
        assert_eq!(peek_sequence(udp.sent.last().expect("packet")), Some(0));

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("unconfirmed rekey must not error");
        assert!(session.rekey_in_flight());

        device.outbound.push_back(ipv4_packet(0x41));
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(961))
            .expect("packet while the rekey is pending");

        let packet = udp.sent.last().expect("packet").clone();
        assert_eq!(
            peek_sequence(&packet),
            Some(1),
            "the old outbound sequence keeps advancing"
        );
        old_outbound_keys
            .decrypt_packet(&packet)
            .expect("the old outbound keys are still in use");
        let new_keys =
            EspKeys::from_negotiation(&rekey_negotiation(&channel)).expect("new rekey keys");
        assert!(
            new_keys.decrypt_packet(&packet).is_err(),
            "the new outbound keys must not be active before confirmation"
        );
    }

    #[test]
    fn a_kmp_303_reply_confirms_and_switches_the_outbound_sa() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let old_outbound_keys = material.outbound_keys.clone();
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let (mut session, channel) =
            rekey_session(material.clone(), now, policy, Duration::from_secs(30));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("rekey sent");
        let negotiation = rekey_negotiation(&channel);

        device.outbound.push_back(ipv4_packet(0x42));
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(961))
            .expect("still on the old SA");
        let before = udp.sent.last().expect("packet").clone();
        old_outbound_keys
            .decrypt_packet(&before)
            .expect("no switch before the confirming signal");

        channel.queue_reply(KMP_CLIENT_CONFIG, 38);
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(962))
            .expect("KMP 303 confirms");
        assert!(!session.rekey_in_flight());
        assert_eq!(session.inbound_spi(), negotiation.outbound_spi);

        device.outbound.push_back(ipv4_packet(0x43));
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(963))
            .expect("switch after confirmation");
        let after = udp.sent.last().expect("packet").clone();
        assert_eq!(
            peek_sequence(&after),
            Some(0),
            "sequence numbers restart after the switch"
        );
        let mut peer = InboundSa::new(
            EspKeys::from_negotiation(&negotiation).expect("peer accepts the new keys"),
        );
        peer.decrypt(&after).expect("the new SA is accepted");
        assert!(
            old_outbound_keys.decrypt_packet(&after).is_err(),
            "the old outbound keys must no longer decrypt"
        );
    }

    #[test]
    fn an_inbound_packet_on_the_new_spi_confirms_and_switches_the_outbound_sa() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let (mut session, channel) =
            rekey_session(material.clone(), now, policy, Duration::from_secs(30));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("rekey sent");
        let negotiation = rekey_negotiation(&channel);
        let new_keys = EspKeys::from_negotiation(&negotiation).expect("new keys");

        let inner = ipv4_packet(0x51);
        let mut new_sender = OutboundSa::new(
            negotiation.outbound_spi,
            new_keys.clone(),
            [0x07; ESP_IV_LEN],
        );
        let packet = new_sender
            .encrypt(&inner, NEXT_HEADER_IPV4)
            .expect("peer packet on the new SPI");
        udp.inject(packet);

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(961))
            .expect("inbound packet confirms the rekey");
        assert!(!session.rekey_in_flight());
        assert_eq!(session.inbound_spi(), negotiation.outbound_spi);
        assert_eq!(device.inbound.last(), Some(&inner));

        device.outbound.push_back(ipv4_packet(0x52));
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(962))
            .expect("outbound after confirmation");
        let packet = udp.sent.last().expect("packet").clone();
        assert_eq!(peek_sequence(&packet), Some(0));
        let mut peer = InboundSa::new(new_keys);
        peer.decrypt(&packet).expect("the new SA is accepted");
    }

    #[test]
    fn a_208_byte_server_302_switches_the_outbound_sa_immediately() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(None, None, 0, 0);
        let (mut session, channel) =
            rekey_session(material.clone(), now, policy, Duration::from_secs(30));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        let block = key_block_fixture();
        let record = server_rekey_302(
            0x2b4c_f4b3,
            EspEncryption::Aes128Cbc,
            EspAuthentication::HmacSha1,
            &block,
            Some((1_000_000, 1200)),
            36,
        );
        assert_eq!(record.len(), 208, "the live gateway 302 was 208 bytes");
        channel.queue_message(record);

        session
            .poll_once(&mut udp, &mut device, now)
            .expect("a server-driven 302 must install the outbound SA");

        assert_eq!(session.outbound().spi(), 0x2b4c_f4b3);
        assert_eq!(
            session.outbound().keys().encryption(),
            EspEncryption::Aes128Cbc
        );
        assert_eq!(
            session.outbound().keys().authentication(),
            EspAuthentication::HmacSha1
        );
        assert_eq!(session.outbound().keys().encryption_key_len(), 16);
        assert_eq!(session.outbound().keys().hmac_key_len(), 20);
        assert_eq!(session.rekey_policy().lifetime_bytes, Some(1_000_000));
        assert_eq!(session.rekey_policy().lifetime_seconds, Some(1200));
        assert_eq!(session.rekey_policy().margin_seconds, 240);

        device.outbound.push_back(ipv4_packet(0x71));
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(1))
            .expect("a packet after the server-driven rekey");
        let packet = udp.sent.last().expect("packet");
        assert_eq!(peek_spi(packet), Some(0x2b4c_f4b3));
        assert_eq!(
            peek_sequence(packet),
            Some(0),
            "the sequence number resets with the peer's SA"
        );
        keys_from_block(
            &block,
            EspEncryption::Aes128Cbc,
            EspAuthentication::HmacSha1,
        )
        .decrypt_packet(packet)
        .expect("the supplied key block decrypts the packet");
        assert!(
            material.outbound_keys.decrypt_packet(packet).is_err(),
            "the previous outbound keys are no longer active"
        );
    }

    #[test]
    fn the_server_302_key_block_split_honours_aes256_and_sha1() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(None, None, 0, 0);
        let (mut session, channel) =
            rekey_session(material.clone(), now, policy, Duration::from_secs(30));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        let block = key_block_fixture();
        let record = server_rekey_302(
            0x0bad_cafe,
            EspEncryption::Aes256Cbc,
            EspAuthentication::HmacSha1,
            &block,
            None,
            0,
        );
        channel.queue_message(record);
        session
            .poll_once(&mut udp, &mut device, now)
            .expect("server-driven 302 with AES-256/SHA1");

        assert_eq!(
            session.outbound().keys().encryption(),
            EspEncryption::Aes256Cbc
        );
        assert_eq!(
            session.outbound().keys().authentication(),
            EspAuthentication::HmacSha1
        );
        assert_eq!(
            session.outbound().keys().encryption_key_len(),
            32,
            "AES-256 consumes the first 32 bytes of the key block"
        );
        assert_eq!(
            session.outbound().keys().hmac_key_len(),
            20,
            "SHA1 consumes the next 20 bytes"
        );

        device.outbound.push_back(ipv4_packet(0x72));
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(1))
            .expect("packet with the split keys");
        let packet = udp.sent.last().expect("packet");
        keys_from_block(
            &block,
            EspEncryption::Aes256Cbc,
            EspAuthentication::HmacSha1,
        )
        .decrypt_packet(packet)
        .expect("the 0x40 split honours AES-256 and SHA1 lengths");
    }

    #[test]
    fn a_server_302_with_a_non_esp_group_is_rejected() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(None, None, 0, 0);
        let (mut session, channel) =
            rekey_session(material.clone(), now, policy, Duration::from_secs(30));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();
        let original_spi = session.outbound().spi();

        let block = key_block_fixture();
        let mut group7 = Vec::new();
        push_attribute(&mut group7, 1, &0x1122_3344u32.to_be_bytes());
        push_attribute(&mut group7, 2, &block);
        let mut group6 = Vec::new();
        push_attribute(&mut group6, 2, &1396u32.to_be_bytes());
        let mut payload = Vec::new();
        push_group(&mut payload, 7, &group7);
        push_group(&mut payload, 6, &group6);
        channel.queue_message(kmp_record(crate::ncp::KMP_ESP_NEGOTIATION, &payload));

        session
            .poll_once(&mut udp, &mut device, now)
            .expect("an invalid 302 must be dropped, not end the tunnel");

        assert_eq!(session.outbound().spi(), original_spi);
        assert!(
            channel.sent().is_empty(),
            "an invalid 302 must not trigger a reply"
        );
    }

    #[test]
    fn a_truncated_server_302_attribute_is_rejected() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(None, None, 0, 0);
        let (mut session, channel) =
            rekey_session(material.clone(), now, policy, Duration::from_secs(30));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();
        let original_spi = session.outbound().spi();

        let block = key_block_fixture();
        let mut group7 = Vec::new();
        push_attribute(&mut group7, 1, &0x5566_7788u32.to_be_bytes());
        push_attribute(&mut group7, 2, &block);
        let mut group8 = Vec::new();
        group8.extend_from_slice(&1u16.to_be_bytes());
        group8.extend_from_slice(&100u32.to_be_bytes());
        let mut payload = Vec::new();
        push_group(&mut payload, 7, &group7);
        payload.extend_from_slice(&8u16.to_be_bytes());
        payload.extend_from_slice(&(group8.len() as u32).to_be_bytes());
        payload.extend_from_slice(&group8);
        channel.queue_message(kmp_record(crate::ncp::KMP_ESP_NEGOTIATION, &payload));

        session
            .poll_once(&mut udp, &mut device, now)
            .expect("a truncated 302 must be dropped, not end the tunnel");

        assert_eq!(session.outbound().spi(), original_spi);
        assert!(
            channel.sent().is_empty(),
            "a truncated 302 must not trigger a reply"
        );
    }

    #[test]
    fn installing_the_peers_keys_restarts_the_local_rekey_timer() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let (mut session, channel) =
            rekey_session(material.clone(), now, policy, Duration::from_secs(30));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        let block = key_block_fixture();
        channel.queue_message(server_rekey_302(
            0x0102_0304,
            EspEncryption::Aes128Cbc,
            EspAuthentication::HmacSha1,
            &block,
            None,
            0,
        ));
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("server-driven rekey at the old 80 percent point");
        assert_eq!(
            channel.sent().len(),
            2,
            "only our answer (302 then 303) is sent"
        );

        for seconds in [961u64, 1919] {
            session
                .poll_once(&mut udp, &mut device, now + Duration::from_secs(seconds))
                .expect("no client-initiated rekey after the peer's keys");
            assert_eq!(
                channel.sent().len(),
                2,
                "the timer restarted when the peer's keys were installed"
            );
        }

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(1920))
            .expect("the client fallback is due one full lifetime later");
        assert_eq!(
            channel.sent().len(),
            4,
            "the fallback rekey runs after a fresh 80 percent lifetime"
        );
    }

    #[test]
    fn an_inbound_302_during_a_pending_exchange_is_applied_without_a_second_proposal() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let (mut session, channel) =
            rekey_session(material.clone(), now, policy, Duration::from_secs(30));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("client-initiated rekey starts");
        assert_eq!(channel.sent().len(), 2);
        assert!(session.rekey_in_flight());
        let client_negotiation = rekey_negotiation(&channel);

        let block = key_block_fixture();
        channel.queue_message(server_rekey_302(
            0x0a0b_0c0d,
            EspEncryption::Aes128Cbc,
            EspAuthentication::HmacSha1,
            &block,
            None,
            0,
        ));
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(961))
            .expect("the peer's keys are applied mid-exchange");

        assert_eq!(session.outbound().spi(), 0x0a0b_0c0d);
        assert!(
            session.rekey_in_flight(),
            "the client-initiated exchange is still pending"
        );
        assert_eq!(
            channel.sent().len(),
            2,
            "no second proposal is sent during an exchange in flight"
        );

        channel.queue_reply(KMP_CLIENT_CONFIG, 38);
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(962))
            .expect("the pending exchange confirms");
        assert!(!session.rekey_in_flight());
        assert_eq!(
            session.inbound_spi(),
            client_negotiation.outbound_spi,
            "the client-proposed inbound SA becomes current"
        );
        assert_eq!(
            session.outbound().spi(),
            0x0a0b_0c0d,
            "confirmation must not overwrite the peer-supplied outbound SA"
        );
    }

    #[test]
    fn the_previous_inbound_sa_survives_the_server_driven_grace_window() {
        let (gateway_keys, _client_keys, material) = session_material();
        let now = Instant::now();
        let old_spi = material.inbound_spi;
        let old_keys = material.inbound_keys.clone();
        let policy = RekeyPolicy::new(None, None, 0, 0);
        let grace = Duration::from_secs(60);
        let (mut session, channel) = rekey_session(material, now, policy, grace);
        let mut udp = FakeUdp::silent(gateway_keys, old_spi, old_keys.clone());
        let mut device = FakeDevice::default();

        let block = key_block_fixture();
        channel.queue_message(server_rekey_302(
            0x0f0e_0d0c,
            EspEncryption::Aes128Cbc,
            EspAuthentication::HmacSha1,
            &block,
            None,
            0,
        ));
        session
            .poll_once(&mut udp, &mut device, now)
            .expect("server-driven rekey");

        let reply = rekey_negotiation(&channel);
        let new_keys = EspKeys::from_negotiation(&reply).expect("our inbound keys");
        assert_eq!(
            session.inbound_spi(),
            reply.outbound_spi,
            "our proposed inbound SPI is current immediately"
        );

        let old_inner = ipv4_packet(0x31);
        let mut old_sender = OutboundSa::new(old_spi, old_keys, [0x01; ESP_IV_LEN]);
        let old_packet = old_sender
            .encrypt(&old_inner, NEXT_HEADER_IPV4)
            .expect("old packet");
        udp.inject(old_packet.clone());
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(1))
            .expect("old SPI during grace");
        assert_eq!(device.inbound.last(), Some(&old_inner));

        let new_inner = ipv4_packet(0x32);
        let mut new_sender = OutboundSa::new(reply.outbound_spi, new_keys, [0x02; ESP_IV_LEN]);
        let new_packet = new_sender
            .encrypt(&new_inner, NEXT_HEADER_IPV4)
            .expect("new packet");
        udp.inject(new_packet);
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(2))
            .expect("new SPI");
        assert_eq!(device.inbound.last(), Some(&new_inner));

        let after_grace = now + grace + Duration::from_secs(1);
        session
            .poll_once(&mut udp, &mut device, after_grace)
            .expect("retire the old inbound SA");

        udp.inject(old_packet);
        session
            .poll_once(&mut udp, &mut device, after_grace + Duration::from_secs(1))
            .expect("old SPI after grace");
        assert_eq!(
            device
                .inbound
                .iter()
                .filter(|packet| *packet == &old_inner)
                .count(),
            1,
            "the old inbound SA is accepted only during the grace window"
        );

        let still_new = new_sender
            .encrypt(&ipv4_packet(0x33), NEXT_HEADER_IPV4)
            .expect("new SPI after grace");
        udp.inject(still_new);
        session
            .poll_once(&mut udp, &mut device, after_grace + Duration::from_secs(2))
            .expect("new SPI after grace");
        assert_eq!(device.inbound.last(), Some(&ipv4_packet(0x33)));
    }

    #[test]
    fn an_unconfirmed_rekey_is_abandoned_after_the_window_and_retried_with_backoff() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let old_outbound_keys = material.outbound_keys.clone();
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let grace = Duration::from_secs(30);
        let (mut session, channel) = rekey_session(material.clone(), now, policy, grace);
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("first attempt");
        assert_eq!(channel.sent().len(), 2);
        assert!(session.rekey_in_flight());

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(980))
            .expect("still inside the confirmation window");
        assert_eq!(
            channel.sent().len(),
            2,
            "no second KMP 302 while one is pending"
        );

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(990))
            .expect("an unconfirmed rekey must not end the tunnel");
        assert!(!session.rekey_in_flight());
        assert_eq!(channel.sent().len(), 2);

        device.outbound.push_back(ipv4_packet(0x60));
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(991))
            .expect("the old SA still carries traffic");
        let packet = udp.sent.last().expect("packet").clone();
        old_outbound_keys
            .decrypt_packet(&packet)
            .expect("the old outbound SA survived the abandoned rekey");

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(1049))
            .expect("before the first backoff");
        assert_eq!(
            channel.sent().len(),
            2,
            "the retry waits for the 60 s backoff"
        );

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(1050))
            .expect("retry after the backoff");
        assert_eq!(channel.sent().len(), 4);
        assert!(session.rekey_in_flight());
    }

    #[test]
    fn a_stale_kmp_reply_cannot_confirm_a_later_attempt() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let grace = Duration::from_secs(30);
        let (mut session, channel) = rekey_session(material.clone(), now, policy, grace);
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("first attempt");
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(990))
            .expect("first attempt abandoned");
        assert!(!session.rekey_in_flight());

        // A reply to the abandoned attempt is still queued when the retry runs.
        channel.queue_reply(KMP_CLIENT_CONFIG, 38);
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(1050))
            .expect("retry");
        assert!(
            session.rekey_in_flight(),
            "the stale reply must be drained, not used to confirm the new attempt"
        );
        assert_eq!(channel.sent().len(), 4);
    }

    #[test]
    fn old_inbound_spi_decrypts_only_during_the_grace_window() {
        let (gateway_keys, _client_keys, material) = session_material();
        let now = Instant::now();
        let old_spi = material.inbound_spi;
        let old_keys = material.inbound_keys.clone();
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let grace = Duration::from_secs(60);
        let (mut session, channel) = rekey_session(material, now, policy, grace);
        let mut udp = FakeUdp::silent(gateway_keys, old_spi, old_keys.clone());
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("rekey");

        let negotiation = rekey_negotiation(&channel);
        let new_keys = EspKeys::from_negotiation(&negotiation).expect("new keys");

        // Confirm the rekey so the old inbound SA enters its grace window.
        let confirmed_at = now + Duration::from_secs(961);
        channel.queue_reply(KMP_CLIENT_CONFIG, 38);
        session
            .poll_once(&mut udp, &mut device, confirmed_at)
            .expect("confirmed");
        assert_eq!(
            session.inbound_spi(),
            negotiation.outbound_spi,
            "the new inbound SPI is current after confirmation"
        );

        let old_inner = ipv4_packet(0x31);
        let mut old_sender = OutboundSa::new(old_spi, old_keys, [0x01; ESP_IV_LEN]);
        let old_packet = old_sender
            .encrypt(&old_inner, NEXT_HEADER_IPV4)
            .expect("old packet");
        udp.inject(old_packet.clone());
        session
            .poll_once(&mut udp, &mut device, confirmed_at + Duration::from_secs(1))
            .expect("old SPI during grace");
        assert_eq!(device.inbound.last(), Some(&old_inner));

        let new_inner = ipv4_packet(0x32);
        let mut new_sender =
            OutboundSa::new(negotiation.outbound_spi, new_keys, [0x02; ESP_IV_LEN]);
        let new_packet = new_sender
            .encrypt(&new_inner, NEXT_HEADER_IPV4)
            .expect("new packet");
        udp.inject(new_packet);
        session
            .poll_once(&mut udp, &mut device, confirmed_at + Duration::from_secs(2))
            .expect("new SPI");
        assert_eq!(device.inbound.last(), Some(&new_inner));

        let after_grace = confirmed_at + grace + Duration::from_secs(1);
        session
            .poll_once(&mut udp, &mut device, after_grace)
            .expect("retire old SA");

        udp.inject(old_packet);
        session
            .poll_once(&mut udp, &mut device, after_grace + Duration::from_secs(1))
            .expect("old SPI after grace");
        assert_eq!(device.inbound.len(), 2, "the retired SPI is refused");
        assert_eq!(
            device
                .inbound
                .iter()
                .filter(|packet| *packet == &old_inner)
                .count(),
            1,
            "the old SPI was accepted only once, during the grace window"
        );
    }

    #[test]
    fn a_second_rekey_cannot_start_while_one_is_pending() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(Some(10), None, 8, 0);
        let grace = Duration::from_secs(100);
        let (mut session, channel) = rekey_session(material.clone(), now, policy, grace);
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(2))
            .expect("first rekey");
        assert_eq!(channel.sent().len(), 2);

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(4))
            .expect("due but already pending");
        assert_eq!(
            channel.sent().len(),
            2,
            "no second rekey while one is awaiting confirmation"
        );
        assert!(session.rekey_in_flight());
    }

    #[test]
    fn a_failed_kmp_send_keeps_the_tunnel_and_retries_later() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let policy = RekeyPolicy::new(Some(1200), None, 240, 0);
        let mut session = EspSession::new(
            material.clone(),
            [0x5a; ESP_IV_LEN],
            EspSessionConfig {
                keepalive_interval_seconds: 100_000,
                peer_timeout: Duration::from_secs(100_000),
                rekey_policy: policy,
                rekey_grace: Duration::from_secs(30),
                mtu: 1396,
            },
            now,
        );
        let channel = SharedKmp::with_failure(0);
        session.set_kmp_channel(Box::new(channel.clone()));
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(960))
            .expect("a failed KMP send must not end the tunnel");
        assert!(!session.rekey_in_flight());
        assert!(channel.sent().is_empty());

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(1020))
            .expect("retry after the backoff");
        assert_eq!(channel.sent().len(), 2);
        assert!(session.rekey_in_flight());
    }

    #[test]
    fn a_disabled_rekey_policy_never_sends_kmp() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let (mut session, channel) = rekey_session(
            material.clone(),
            now,
            RekeyPolicy::new(None, None, 0, 0),
            Duration::from_secs(30),
        );
        let mut udp = FakeUdp::silent(gateway_keys, material.inbound_spi, client_keys);
        let mut device = FakeDevice::default();

        for seconds in [1u64, 1000, 50_000] {
            session
                .poll_once(&mut udp, &mut device, now + Duration::from_secs(seconds))
                .expect("a disabled rekey policy is never due");
        }
        assert!(channel.sent().is_empty(), "no KMP message is sent");
    }

    #[test]
    fn session_round_trips_a_packet_through_a_fake_udp_and_device() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let mut session = new_session(material, now);
        let mut udp = FakeUdp::echo(gateway_keys, 0x3333_4444, client_keys);
        let mut device = FakeDevice::default();

        let packet = ipv4_packet(0x11);
        device.outbound.push_back(packet.clone());

        assert!(session
            .poll_once(&mut udp, &mut device, now)
            .expect("outbound"));
        assert_eq!(udp.sent.len(), 1);
        assert!(device.inbound.is_empty());

        assert!(session
            .poll_once(&mut udp, &mut device, now + Duration::from_millis(1))
            .expect("inbound"));
        assert_eq!(device.inbound, vec![packet]);
        assert_eq!(session.bytes_sent(), udp.sent[0].len() as u64);
        assert!(session.bytes_received() > 0);
    }

    #[test]
    fn session_drops_replayed_inbound_packets() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let mut session = new_session(material, now);
        let mut udp = FakeUdp::silent(gateway_keys, 0x3333_4444, client_keys.clone());
        let mut device = FakeDevice::default();

        let mut sender = OutboundSa::new(0x3333_4444, client_keys, [0x77; ESP_IV_LEN]);
        let packet = sender
            .encrypt(&ipv4_packet(0x22), NEXT_HEADER_IPV4)
            .expect("encrypt");
        udp.inject(packet.clone());
        udp.inject(packet);

        session
            .poll_once(&mut udp, &mut device, now)
            .expect("first");
        session
            .poll_once(&mut udp, &mut device, now + Duration::from_millis(1))
            .expect("replay dropped");
        assert_eq!(device.inbound.len(), 1);
    }

    #[test]
    fn malformed_packets_are_dropped_without_panicking() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let mut session = new_session(material, now);
        let mut udp = FakeUdp::silent(gateway_keys, 0x3333_4444, client_keys.clone());
        let mut device = FakeDevice::default();

        udp.inject(vec![0x33, 0x33, 0x44, 0x44]);
        udp.inject(vec![0xff; 5]);
        udp.inject(vec![0x00; 3]);
        udp.inject(vec![0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0]);

        let mut sender = OutboundSa::new(0x3333_4444, client_keys, [0x44; ESP_IV_LEN]);
        let mut bad_icv = sender
            .encrypt(b"\x45tampered", NEXT_HEADER_IPV4)
            .expect("encrypt");
        let last = bad_icv.len() - 1;
        bad_icv[last] ^= 0x80;
        udp.inject(bad_icv);

        for step in 0..5 {
            session
                .poll_once(&mut udp, &mut device, now + Duration::from_millis(step))
                .expect("a malformed packet must not end the session");
        }
        assert!(device.inbound.is_empty());
    }

    #[test]
    fn session_reports_an_unresponsive_peer() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let mut session = new_session(material, now);
        let mut udp = FakeUdp::silent(gateway_keys, 0x3333_4444, client_keys);
        let mut device = FakeDevice::default();

        let error = session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(91))
            .expect_err("the peer must time out");
        assert!(matches!(error, EspSessionError::PeerUnresponsive(_)));
    }

    #[test]
    fn session_sends_keepalives_on_the_configured_interval() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let mut session = new_session(material, now);
        let mut udp = FakeUdp::echo(gateway_keys.clone(), 0x3333_4444, client_keys);
        let mut device = FakeDevice::default();

        session
            .poll_once(&mut udp, &mut device, now + Duration::from_secs(31))
            .expect("keepalive");
        assert_eq!(udp.sent.len(), 1);
        let decrypted = gateway_keys
            .decrypt_packet(&udp.sent[0])
            .expect("keepalive decrypts");
        assert_eq!(decrypted.payload, vec![0u8]);
        assert_eq!(decrypted.next_header, NEXT_HEADER_IPV4);
    }

    struct RecordingUdp {
        recv_calls: usize,
    }

    impl EspUdp for RecordingUdp {
        fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
            Ok(packet.len())
        }

        fn recv(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            self.recv_calls += 1;
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    #[test]
    fn a_single_poll_drains_a_full_device_batch() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let mut session = new_session(material, now);
        let mut udp = FakeUdp::silent(gateway_keys, 0x3333_4444, client_keys);
        let mut device = FakeDevice::default();
        for marker in 0..ESP_BATCH_MAX {
            device.outbound.push_back(ipv4_packet(marker as u8));
        }

        assert!(session
            .poll_once(&mut udp, &mut device, now)
            .expect("batch poll"));
        assert_eq!(
            udp.sent.len(),
            ESP_BATCH_MAX,
            "one poll must drain the whole device batch, not one packet"
        );
        assert!(device.outbound.is_empty());
    }

    #[test]
    fn a_poll_stops_at_the_batch_cap_and_finishes_next_time() {
        let (gateway_keys, client_keys, material) = session_material();
        let now = Instant::now();
        let mut session = new_session(material, now);
        let mut udp = FakeUdp::silent(gateway_keys, 0x3333_4444, client_keys);
        let mut device = FakeDevice::default();
        for marker in 0..=ESP_BATCH_MAX {
            device.outbound.push_back(ipv4_packet(marker as u8));
        }

        assert!(session
            .poll_once(&mut udp, &mut device, now)
            .expect("first batch"));
        assert_eq!(udp.sent.len(), ESP_BATCH_MAX);
        assert_eq!(device.outbound.len(), 1);

        assert!(session
            .poll_once(&mut udp, &mut device, now + Duration::from_millis(1))
            .expect("remaining packet"));
        assert_eq!(udp.sent.len(), ESP_BATCH_MAX + 1);
        assert!(device.outbound.is_empty());
    }

    #[test]
    fn an_empty_nonblocking_socket_returns_immediately() {
        let (_gateway_keys, _client_keys, material) = session_material();
        let now = Instant::now();
        let mut session = new_session(material, now);
        let mut udp = RecordingUdp { recv_calls: 0 };
        let mut device = FakeDevice::default();

        let started = Instant::now();
        let worked = session
            .poll_once(&mut udp, &mut device, now)
            .expect("empty poll");
        let elapsed = started.elapsed();

        assert!(!worked);
        assert_eq!(udp.recv_calls, 1, "the socket is probed once, not retried");
        assert!(
            elapsed < Duration::from_millis(90),
            "an empty socket must not wait for a read timeout; took {elapsed:?}"
        );
    }

    #[test]
    #[ignore = "timing-sensitive throughput benchmark; run with --ignored --nocapture"]
    fn esp_encrypt_decrypt_throughput_benchmark() {
        const PACKETS: usize = 20_000;
        let keys = keys(EspEncryption::Aes128Cbc, EspAuthentication::HmacSha1, 0x42);
        let payload = vec![0x45u8; 1400];

        let mut outbound = OutboundSa::new(0x1a2b_3c4d, keys.clone(), [0x11; ESP_IV_LEN]);
        let mut inbound = InboundSa::new(keys.clone());
        let baseline_start = Instant::now();
        for _ in 0..PACKETS {
            let packet = outbound
                .encrypt(&payload, NEXT_HEADER_IPV4)
                .expect("baseline encrypt");
            let decrypted = inbound.decrypt(&packet).expect("baseline decrypt");
            debug_assert_eq!(decrypted.payload.len(), payload.len());
        }
        let baseline = baseline_start.elapsed();

        let mut outbound = OutboundSa::new(0x1a2b_3c4d, keys.clone(), [0x11; ESP_IV_LEN]);
        let mut inbound = InboundSa::new(keys);
        let mut wire = vec![0u8; payload.len() + 128];
        let mut plain = vec![0u8; payload.len() + 128];
        let reuse_start = Instant::now();
        for _ in 0..PACKETS {
            let length = outbound
                .encrypt_into(&payload, NEXT_HEADER_IPV4, &mut wire)
                .expect("buffer encrypt");
            let decrypted = inbound
                .decrypt_into(&wire[..length], &mut plain)
                .expect("buffer decrypt");
            debug_assert_eq!(decrypted.payload.len(), payload.len());
        }
        let reuse = reuse_start.elapsed();

        let baseline_pps = PACKETS as f64 / baseline.as_secs_f64();
        let reuse_pps = PACKETS as f64 / reuse.as_secs_f64();
        let wire_bits = (payload.len() + 62) as f64 * 8.0;
        eprintln!(
            "ESP encrypt+decrypt baseline (Vec per packet): {baseline_pps:.0} pkt/s, {:.1} Mbit/s",
            baseline_pps * wire_bits / 1e6
        );
        eprintln!(
            "ESP encrypt+decrypt buffer reuse:              {reuse_pps:.0} pkt/s, {:.1} Mbit/s",
            reuse_pps * wire_bits / 1e6
        );
        eprintln!(
            "speedup: {:.2}x over {PACKETS} packets",
            reuse_pps / baseline_pps
        );
        assert!(
            reuse < Duration::from_secs(10),
            "buffer-reuse encrypt+decrypt is unexpectedly slow: {reuse:?}"
        );
    }
}
