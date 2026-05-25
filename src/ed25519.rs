//! Ed25519 classical signatures.
//!
//! Uses `ed25519-dalek` v2 (RFC 8032). Keys are zeroed on drop.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

use crate::{Error, Result};

/// Generate a fresh Ed25519 keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// Sign `message` with `key`. Never fails.
pub fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    use ed25519_dalek::Signer;
    key.sign(message)
}

/// Verify `sig` over `message` with `vk`. Returns `Ok(())` on success.
pub fn verify(vk: &VerifyingKey, message: &[u8], sig: &Signature) -> Result<()> {
    use ed25519_dalek::Verifier;
    vk.verify(message, sig).map_err(|_| Error::Verify)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let (sk, vk) = generate_keypair();
        let msg = b"brigid test message";
        let sig = sign(&sk, msg);
        assert!(verify(&vk, msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let (sk, vk) = generate_keypair();
        let msg = b"original";
        let sig = sign(&sk, msg);
        assert!(verify(&vk, b"tampered", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let msg = b"message";
        let sig = sign(&sk, msg);
        assert!(verify(&vk2, msg, &sig).is_err());
    }
}
