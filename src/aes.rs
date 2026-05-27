//! AES-256-GCM authenticated encryption.
//!
//! - Nonce: 96-bit random, generated via OsRng, never reused.
//! - Plaintext is returned as `Zeroizing<Vec<u8>>` (zeroed on drop).
//! - All errors are opaque — no oracle information leaked.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use zeroize::Zeroizing;

use crate::{Error, MasterKey, Result};

/// An encrypted blob: nonce + authenticated ciphertext.
/// Suitable for serialisation to storage.
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    /// Serialise to `nonce || ciphertext`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserialise from `nonce || ciphertext`. Minimum length: 28 bytes (12 + 16 GCM tag).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 28 {
            return Err(Error::Decrypt);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[..12]);
        Ok(Self {
            nonce,
            ciphertext: bytes[12..].to_vec(),
        })
    }
}

/// Encrypt `plaintext` with `key` (32 bytes). Nonce is chosen randomly.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_arr = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce_arr, plaintext)
        .map_err(|_| Error::Encrypt)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_arr);
    Ok(EncryptedBlob { nonce, ciphertext })
}

/// Decrypt `blob` with `key`. Returns plaintext zeroed on drop.
pub fn decrypt(key: &[u8; 32], blob: &EncryptedBlob) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&blob.nonce);
    let plaintext = cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

/// Encrypt using a key derived from the master key.
///
/// Uses [`crate::hkdf::derive_user_key`] with `user_id = b"aes-data-encryption"`
/// and `purpose = b"v1"` to derive a 32-byte AES-256-GCM subkey, avoiding direct
/// reuse of the master key across different cryptographic contexts. The actual
/// HKDF `info` is: `"brigid-user-key-v1" || u32_be(18) || "aes-data-encryption"
/// || u32_be(2) || "v1"`.
pub fn encrypt_with_master(master: &MasterKey, plaintext: &[u8]) -> Result<EncryptedBlob> {
    let subkey = crate::hkdf::derive_user_key(master, b"aes-data-encryption", b"v1")?;
    encrypt(&*subkey, plaintext)
}

/// Decrypt using a key derived from the master key.
///
/// Derives the same subkey as [`encrypt_with_master`] so round-trips are
/// consistent.
pub fn decrypt_with_master(master: &MasterKey, blob: &EncryptedBlob) -> Result<Zeroizing<Vec<u8>>> {
    let subkey = crate::hkdf::derive_user_key(master, b"aes-data-encryption", b"v1")?;
    decrypt(&*subkey, blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42; 32]
    }

    #[test]
    fn round_trip() {
        let key = test_key();
        let plaintext = b"hello brigid";
        let blob = encrypt(&key, plaintext).unwrap();
        let recovered = decrypt(&key, &blob).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = test_key();
        let plaintext = b"secret";
        let blob = encrypt(&key, plaintext).unwrap();
        let wrong_key = [0x00; 32];
        assert!(decrypt(&wrong_key, &blob).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let mut blob = encrypt(&key, b"secret").unwrap();
        blob.ciphertext[0] ^= 0xff;
        assert!(decrypt(&key, &blob).is_err());
    }

    #[test]
    fn distinct_nonces() {
        let key = test_key();
        let b1 = encrypt(&key, b"msg").unwrap();
        let b2 = encrypt(&key, b"msg").unwrap();
        // Two successive encryptions must produce distinct nonces.
        assert_ne!(b1.nonce, b2.nonce);
    }

    #[test]
    fn serialization_round_trip() {
        let key = test_key();
        let blob = encrypt(&key, b"test").unwrap();
        let bytes = blob.to_bytes();
        let blob2 = EncryptedBlob::from_bytes(&bytes).unwrap();
        let recovered = decrypt(&key, &blob2).unwrap();
        assert_eq!(recovered.as_slice(), b"test");
    }

    #[test]
    fn from_bytes_too_short() {
        assert!(EncryptedBlob::from_bytes(&[0u8; 10]).is_err());
    }
}
