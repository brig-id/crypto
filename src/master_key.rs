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

    // The `BRIGID_MASTER_KEY` environment variable is process-global, so all
    // env-based assertions live in a single test to avoid races with the
    // parallel test runner. No other test touches this variable.
    #[test]
    fn from_env_paths() {
        const VAR: &str = "BRIGID_MASTER_KEY";

        // Unset → error.
        // SAFETY: single-threaded within this test; no other test reads or
        // writes `BRIGID_MASTER_KEY`.
        unsafe { std::env::remove_var(VAR) };
        assert!(MasterKey::from_env().is_err());

        // Valid 64-hex → ok.
        unsafe { std::env::set_var(VAR, "cd".repeat(32)) };
        let key = MasterKey::from_env().expect("valid hex must load");
        assert_eq!(key.expose(), &[0xcd; 32]);

        // Wrong length → error.
        unsafe { std::env::set_var(VAR, "cd".repeat(31)) };
        assert!(MasterKey::from_env().is_err());

        // Clean up so we never leave key material in the environment.
        unsafe { std::env::remove_var(VAR) };
    }

    #[cfg(unix)]
    #[test]
    fn from_env_non_utf8() {
        use std::os::unix::ffi::OsStrExt;
        const VAR: &str = "BRIGID_MASTER_KEY_NON_UTF8";

        let invalid = std::ffi::OsStr::from_bytes(&[0x66, 0x80, 0x80]);
        // Exercise the non-UTF-8 conversion path directly (rather than via the
        // process environment) so the assertion is hermetic.
        assert!(os_string_into_zeroizing_string(invalid.to_os_string()).is_err());

        // Sanity: the valid path returns the same string.
        let ok = os_string_into_zeroizing_string("deadbeef".into()).expect("valid utf-8");
        assert_eq!(&*ok, "deadbeef");
        let _ = VAR;
    }

    #[test]
    fn from_file_valid_and_missing() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("brigid-master-key-test-{}", std::process::id()));

        std::fs::write(&path, format!("{}\n", "ef".repeat(32))).expect("write temp key file");
        let key = MasterKey::from_file(&path).expect("valid key file must load");
        assert_eq!(key.expose(), &[0xef; 32]);
        std::fs::remove_file(&path).ok();

        // Missing file → error (I/O error propagated).
        let missing = dir.join("brigid-master-key-does-not-exist-xyz");
        assert!(MasterKey::from_file(&missing).is_err());
    }
}
