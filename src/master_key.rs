//! MASTER_KEY loading and validation.
//!
//! The master key is 32 bytes (256 bits), stored as a hex-encoded 64-character
//! string in the `BRIGID_MASTER_KEY` environment variable or a key file.
//! It is never logged or included in error messages.

use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Wrapper around the 32-byte master key.
/// Zeroed on drop via `secrecy::Secret`.
pub struct MasterKey(Secret<[u8; 32]>);

impl MasterKey {
    /// Load from `BRIGID_MASTER_KEY` environment variable (64 hex chars).
    pub fn from_env() -> Result<Self> {
        // Read as `OsString` so we own the raw bytes and can zeroize them on
        // every exit path (including the non-UTF-8 error path). `std::env::var`
        // would otherwise drop the offending `OsString` from
        // `VarError::NotUnicode(_)` without wiping it, leaving an extra copy
        // of potential key material in process memory.
        let raw_os = match std::env::var_os("BRIGID_MASTER_KEY") {
            Some(v) => v,
            None => {
                return Err(Error::InvalidMasterKey(
                    "master key environment variable not set",
                ));
            }
        };
        let hex_str = os_string_into_zeroizing_string(raw_os).map_err(|_| {
            // Surface the precise failure without echoing the offending
            // bytes (they may carry user data and must never appear in
            // logs). The variable name is also omitted from the message
            // per AGENTS.md (`BRIGID_MASTER_KEY` must never appear in
            // logs, panics, or error messages).
            Error::InvalidMasterKey("master key environment variable contains non-UTF-8 bytes")
        })?;
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
        let mut bytes = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(hex_str, &mut *bytes)?;
        // `std::mem::take` moves the array out of the `Zeroizing` buffer and
        // replaces it with `[0; 32]` in a single step, so only one plaintext
        // copy of the key exists at any moment. `Secret::new(*bytes)` would
        // instead copy the array out via `Copy` and leave the original
        // plaintext alive in `bytes` until the function returned, briefly
        // doubling the in-memory footprint of the master key.
        Ok(Self(Secret::new(std::mem::take(&mut *bytes))))
    }

    /// Load from a file containing a hex-encoded key (64 hex chars).
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let contents = Zeroizing::new(std::fs::read_to_string(path)?);
        Self::from_hex(contents.trim())
    }

    /// Expose raw key bytes (crate-internal only).
    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// Convert an owned `OsString` into a `Zeroizing<String>`.
///
/// **Unix:** guarantees the underlying byte buffer is wiped on both the
/// success and the non-UTF-8 error path. The bytes are taken via
/// `OsStringExt::into_vec` and wrapped in `Zeroizing`, so the original
/// allocation is zeroed on drop regardless of which arm matches.
///
/// **Non-unix (Windows / WASI):** best-effort only. `OsString` has no safe
/// byte-level mutate API on these platforms, so the original buffer is
/// dropped without an explicit wipe on the non-UTF-8 error path. The
/// success path is still wrapped in `Zeroizing<String>` so the parsed hex
/// is zeroed once consumed by `from_hex`.
#[cfg(unix)]
fn os_string_into_zeroizing_string(
    os: std::ffi::OsString,
) -> std::result::Result<Zeroizing<String>, ()> {
    use std::os::unix::ffi::OsStringExt;
    let mut bytes = Zeroizing::new(os.into_vec());
    if std::str::from_utf8(&bytes).is_err() {
        return Err(());
    }
    // UTF-8 validity just verified above; take ownership without re-copying.
    let owned = std::mem::take(&mut *bytes);
    // SAFETY: `std::str::from_utf8(&owned)` succeeded immediately above and
    // `owned` is the exact same byte sequence (moved, not modified).
    Ok(Zeroizing::new(unsafe {
        String::from_utf8_unchecked(owned)
    }))
}

#[cfg(not(unix))]
fn os_string_into_zeroizing_string(
    os: std::ffi::OsString,
) -> std::result::Result<Zeroizing<String>, ()> {
    // Non-unix `OsString` has no safe byte-level mutate API, so the
    // original buffer may not be zeroized when it is dropped on the error
    // path. The success path is wrapped in `Zeroizing` for the UTF-8 case.
    os.into_string().map(Zeroizing::new).map_err(|_| ())
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
