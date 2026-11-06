//! Zeroizing secret byte buffers for oNCP and ESP key material.
//!
//! [`SecretKey`] deliberately has no `Serialize` implementation and a `Debug`
//! implementation that prints only the length. Callers must keep the bytes out
//! of logs, JSON and error messages; [`SecretKey::expose`] is the only way to
//! read them.

use std::fmt;

use zeroize::Zeroizing;

/// Key material that is wiped when dropped.
#[derive(Clone)]
pub struct SecretKey(Zeroizing<Vec<u8>>);

impl SecretKey {
    /// Take ownership of a byte buffer as key material.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// Borrow the key bytes. Do not log, print or serialise the result.
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Length of the key in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("redacted", &true)
            .field("length", &self.0.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted_and_zeroizes_on_drop() {
        let key = SecretKey::new(b"0123456789abcdef".to_vec());
        let debug = format!("{key:?}");
        assert!(!debug.contains("0123456789abcdef"));
        assert!(debug.contains("redacted"));
        assert_eq!(key.len(), 16);
        assert!(!key.is_empty());
    }
}
