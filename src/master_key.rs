//! MASTER_KEY loading and validation.
//!
//! The master key is 32 bytes (256 bits), stored as a hex-encoded 64-character
//! string in the `BRIGID_MASTER_KEY` environment variable or a key file.
//! It is never logged or included in error messages.

use secrecy::{ExposeSecret, Secret};

use crate::{Error, Result};

/// Wrapper around the 32-byte master key.
/// Zeroed on drop via `secrecy::Secret`.
pub struct MasterKey(Secret<[u8; 32]>);

impl MasterKey {
    /// Load from `BRIGID_MASTER_KEY` environment variable (64 hex chars).
    pub fn from_env() -> Result<Self> {
        let hex_str = std::env::var("BRIGID_MASTER_KEY")
            .map_err(|_| Error::InvalidMasterKey("BRIGID_MASTER_KEY not set"))?;
        Self::from_hex(&hex_str)
    }

    /// Load from a hex-encoded string (64 hex chars → 32 bytes).
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.trim();
        if hex_str.len() != 64 {
            return Err(Error::InvalidMasterKey(
                "must be exactly 64 hex characters (32 bytes)",
            ));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes)?;
        Ok(Self(Secret::new(bytes)))
    }

    /// Load from a file containing a hex-encoded key (64 hex chars).
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_hex(contents.trim())
    }

    /// Expose raw key bytes (crate-internal only).
    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_hex_valid() {
        let key = MasterKey::from_hex(&"ab".repeat(32)).unwrap();
        assert_eq!(key.expose(), &[0xab; 32]);
    }

    #[test]
    fn from_hex_wrong_length() {
        assert!(MasterKey::from_hex("abc").is_err());
        assert!(MasterKey::from_hex(&"ab".repeat(33)).is_err());
    }

    #[test]
    fn from_hex_invalid_chars() {
        assert!(MasterKey::from_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn from_hex_strips_whitespace() {
        let padded = format!("  {}  ", "ab".repeat(32));
        assert!(MasterKey::from_hex(&padded).is_ok());
    }
}
