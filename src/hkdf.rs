//! HKDF-SHA3-256 key derivation.
//!
//! Domain separation is enforced via the `info` parameter.
//! All derived key material is returned as `Zeroizing<…>` (zeroed on drop).

use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::{Error, MasterKey, Result};

/// Maximum output length for `derive_key` (255 × SHA3-256 block size).
const MAX_DERIVE_KEY_LEN: usize = 8160;

/// Derive `length` bytes of key material from `master` using `info` for domain
/// separation. The `info` string MUST be unique for each key context.
///
/// Returns `Err(KeyDerivation)` if `length` exceeds 8160 bytes.
pub fn derive_key(master: &MasterKey, info: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>> {
    if length > MAX_DERIVE_KEY_LEN {
        return Err(Error::KeyDerivation);
    }
    let hk = Hkdf::<Sha3_256>::new(None, master.expose());
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hk.expand(info, &mut okm)
        .map_err(|_| Error::KeyDerivation)?;
    Ok(okm)
}

/// Derive a 32-byte user-specific key for a given `purpose`.
///
/// The `info` is constructed as:
/// `"brigid-user-key-v1" || u32_be(len(user_id)) || user_id || u32_be(len(purpose)) || purpose`
/// (length-prefixed fields prevent collisions — no separator character is used).
pub fn derive_user_key(
    master: &MasterKey,
    user_id: &[u8],
    purpose: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    // Length-prefix user_id and purpose to prevent injection / collision.
    let uid_len = (user_id.len() as u32).to_be_bytes();
    let pur_len = (purpose.len() as u32).to_be_bytes();
    let mut info = Vec::with_capacity(18 + 4 + user_id.len() + 4 + purpose.len());
    info.extend_from_slice(b"brigid-user-key-v1");
    info.extend_from_slice(&uid_len);
    info.extend_from_slice(user_id);
    info.extend_from_slice(&pur_len);
    info.extend_from_slice(purpose);

    let hk = Hkdf::<Sha3_256>::new(None, master.expose());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *okm)
        .map_err(|_| Error::KeyDerivation)?;
    Ok(okm)
}

/// Low-level HKDF expand used internally (e.g. by the hybrid KEM).
/// `ikm` is zeroized after use by the caller.
pub(crate) fn hkdf_expand_32(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha3_256>::new(None, ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    // 32 bytes < 255 × HashLen — this path is unreachable, but we propagate
    // the error to avoid using expect() on crypto paths.
    hk.expand(info, &mut *okm)
        .map_err(|_| Error::KeyDerivation)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MasterKey;

    fn master() -> MasterKey {
        MasterKey::from_hex(&"01".repeat(32)).unwrap()
    }

    #[test]
    fn derive_key_basic() {
        let k = derive_key(&master(), b"test-context", 32).unwrap();
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn derive_key_different_info_yields_different_key() {
        let k1 = derive_key(&master(), b"context-a", 32).unwrap();
        let k2 = derive_key(&master(), b"context-b", 32).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_user_key_basic() {
        let k = derive_user_key(&master(), b"user123", b"storage").unwrap();
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn derive_user_key_different_users_differ() {
        let k1 = derive_user_key(&master(), b"user1", b"storage").unwrap();
        let k2 = derive_user_key(&master(), b"user2", b"storage").unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_user_key_different_purposes_differ() {
        let k1 = derive_user_key(&master(), b"user1", b"storage").unwrap();
        let k2 = derive_user_key(&master(), b"user1", b"signing").unwrap();
        assert_ne!(*k1, *k2);
    }
}
