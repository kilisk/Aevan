//! RFC 6238 TOTP (SHA-1, six digits, 30 seconds) and RFC 4648 base32.
//!
//! Codes are computed on demand and never cached: the plan forbids reusing a
//! one-time code across attempts.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::store::Secret;

/// Digits used by the gateway realm and the CLI default.
pub const DEFAULT_DIGITS: u32 = 6;
/// Time step in seconds.
pub const DEFAULT_PERIOD: u64 = 30;

/// TOTP configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Totp {
    digits: u32,
    period: u64,
}

impl Default for Totp {
    fn default() -> Self {
        Self {
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
        }
    }
}

impl Totp {
    /// Construct a TOTP configuration.
    ///
    /// `digits` must be between 1 and 10 (inclusive); `period` must be nonzero.
    pub fn new(digits: u32, period: u64) -> Result<Self, TotpError> {
        if !(1..=10).contains(&digits) {
            return Err(TotpError::InvalidDigits(digits));
        }
        if period == 0 {
            return Err(TotpError::InvalidPeriod(period));
        }
        Ok(Self { digits, period })
    }

    /// Number of output digits.
    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// Time step in seconds.
    pub fn period(&self) -> u64 {
        self.period
    }

    /// Generate the code for a raw secret at a Unix timestamp.
    pub fn code_at(&self, secret: &[u8], unix_time: u64) -> Result<String, TotpError> {
        if secret.is_empty() {
            return Err(TotpError::EmptySecret);
        }
        let counter = unix_time / self.period;
        Ok(format_code(hotp(secret, counter, self.digits), self.digits))
    }

    /// Generate the code for the current wall clock.
    pub fn code_now(&self, secret: &[u8]) -> Result<String, TotpError> {
        self.code_at(secret, now_unix())
    }

    /// Seconds until the current code expires.
    pub fn remaining_seconds(&self, unix_time: u64) -> u64 {
        self.period - (unix_time % self.period)
    }
}

/// Raw HOTP value (RFC 4226) modulo `10^digits`.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u64 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((digest[offset] & 0x7f) as u64) << 24
        | (digest[offset + 1] as u64) << 16
        | (digest[offset + 2] as u64) << 8
        | digest[offset + 3] as u64;

    binary % 10u64.pow(digits)
}

/// Decode an RFC 4648 base32 secret (padding optional, separators ignored).
pub fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut output = Vec::with_capacity(input.len() * 5 / 8);

    for character in input.chars() {
        if character.is_whitespace() || character == '-' {
            continue;
        }
        if character == '=' {
            break;
        }

        let value = match character.to_ascii_uppercase() {
            upper @ 'A'..='Z' => upper as u32 - 'A' as u32,
            digit @ '2'..='7' => digit as u32 - '2' as u32 + 26,
            _ => return Err(TotpError::InvalidBase32(character)),
        };

        buffer = (buffer << 5) | value;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
        if bits > 0 {
            buffer &= (1u32 << bits) - 1;
        }
    }

    Ok(output)
}

/// Convenience for a base32 textual secret held in a [`Secret`].
pub fn decode_base32_secret(secret: &Secret) -> Result<Vec<u8>, TotpError> {
    decode_base32(secret.expose())
}

fn format_code(code: u64, digits: u32) -> String {
    let value = code.to_string();
    format!("{value:0>width$}", width = digits as usize)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// TOTP errors.
#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    /// Digit count outside the supported range.
    #[error("invalid TOTP digit count {0}; expected 1..=10")]
    InvalidDigits(u32),
    /// Zero-length time step.
    #[error("invalid TOTP period {0}; expected a positive number of seconds")]
    InvalidPeriod(u64),
    /// Empty HMAC key.
    #[error("TOTP secret must not be empty")]
    EmptySecret,
    /// Character outside the base32 alphabet.
    #[error("invalid base32 character {0:?}")]
    InvalidBase32(char),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-1, 20-byte ASCII secret.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_eight_digit_vectors() {
        let vectors = [
            (59_u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        let totp = Totp::new(8, 30).expect("totp");
        for (time, expected) in vectors {
            assert_eq!(totp.code_at(RFC_SECRET, time).expect("code"), expected);
        }
    }

    #[test]
    fn rfc6238_vectors_truncated_to_six_digits() {
        let vectors = [
            (59_u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ];
        let totp = Totp::default();
        for (time, expected) in vectors {
            assert_eq!(totp.code_at(RFC_SECRET, time).expect("code"), expected);
        }
    }

    #[test]
    fn default_is_six_digits_and_thirty_seconds() {
        assert_eq!(DEFAULT_DIGITS, 6);
        assert_eq!(DEFAULT_PERIOD, 30);
        let totp = Totp::default();
        assert_eq!(totp.digits(), 6);
        assert_eq!(totp.period(), 30);
        assert_eq!(totp.remaining_seconds(0), 30);
        assert_eq!(totp.remaining_seconds(29), 1);
        assert_eq!(totp.remaining_seconds(30), 30);
    }

    #[test]
    fn rejects_bad_configuration() {
        assert!(matches!(Totp::new(0, 30), Err(TotpError::InvalidDigits(0))));
        assert!(matches!(
            Totp::new(11, 30),
            Err(TotpError::InvalidDigits(11))
        ));
        assert!(matches!(Totp::new(6, 0), Err(TotpError::InvalidPeriod(0))));
        assert!(matches!(
            Totp::default().code_at(&[], 0),
            Err(TotpError::EmptySecret)
        ));
    }

    #[test]
    fn base32_decodes_rfc4648_vectors() {
        assert_eq!(decode_base32("MY======").expect("decode"), b"f");
        assert_eq!(decode_base32("MZXQ====").expect("decode"), b"fo");
        assert_eq!(decode_base32("MZXW6===").expect("decode"), b"foo");
        assert_eq!(decode_base32("MZXW6YQ=").expect("decode"), b"foob");
        assert_eq!(decode_base32("MZXW6YTB").expect("decode"), b"fooba");
        assert_eq!(
            decode_base32("MZXW6YTBOI======").expect("decode"),
            b"foobar"
        );
    }

    #[test]
    fn base32_ignores_separators_and_case() {
        assert_eq!(
            decode_base32("mzxw 6ytb-oi").expect("decode"),
            b"foobar".to_vec()
        );
    }

    #[test]
    fn base32_rejects_invalid_characters() {
        assert!(matches!(
            decode_base32("not*base32"),
            Err(TotpError::InvalidBase32('*'))
        ));
        assert!(matches!(
            decode_base32("0189"),
            Err(TotpError::InvalidBase32('0'))
        ));
    }

    #[test]
    fn base32_secret_helper() {
        let secret = Secret::new("MZXW6YTBOI======");
        assert_eq!(decode_base32_secret(&secret).expect("decode"), b"foobar");
    }
}
