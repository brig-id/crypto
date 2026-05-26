//! ML-DSA-65 + Ed25519 hybrid signatures (FIPS 204).
//!
//! Both signatures are required to verify. An attacker must break *both*
//! ML-DSA-65 (post-quantum) and Ed25519 (classical) to forge a signature.
//!
//! Serialised `HybridSignature` format:
//!   4 bytes (u32 BE) — ML-DSA signature length
//!   N bytes          — ML-DSA-65 signature
//!   64 bytes         — Ed25519 signature

use ed25519_dalek::{Signature as Ed25519Signature, SigningKey as Ed25519SigningKey};
use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa65, SignatureEncoding, Signer,
    SigningKey as MlDsaSigningKey, Verifier, VerifyingKey as MlDsaVerifyingKey,
};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Byte length of an ML-DSA-65 signature (fixed by the standard).
const MLDSA65_SIG_LEN: usize = 3309;
/// Byte length of an ML-DSA-65 verifying key (fixed by the standard).
const MLDSA65_VK_LEN: usize = 1952;

/// Hybrid signing (secret) key. Secret material is zeroed on drop.
pub struct HybridDsaSigningKey {
    /// ML-DSA-65 seed (32 bytes, the preferred compact representation).
    mldsa_seed: Zeroizing<Vec<u8>>,
    /// Ed25519 signing key seed (32 bytes).
    ed25519_seed: Zeroizing<[u8; 32]>,
}

/// Hybrid verifying (public) key.
pub struct HybridDsaVerifyingKey {
    mldsa_vk_bytes: Vec<u8>,
    ed25519_vk_bytes: [u8; 32],
}

/// Hybrid signature: ML-DSA-65 signature + Ed25519 signature.
pub struct HybridSignature {
    mldsa_sig: Vec<u8>,
    ed25519_sig: [u8; 64],
}

impl HybridSignature {
    /// Serialise: `u32_be(len_mldsa) || mldsa_sig || ed25519_sig`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.mldsa_sig.len() as u32;
        let mut out = Vec::with_capacity(4 + self.mldsa_sig.len() + 64);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.mldsa_sig);
        out.extend_from_slice(&self.ed25519_sig);
        out
    }

    /// Deserialise from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 + 64 {
            return Err(Error::Verify);
        }
        let ml_len_bytes: [u8; 4] = bytes[..4].try_into().map_err(|_| Error::Verify)?;
        let ml_len = u32::from_be_bytes(ml_len_bytes) as usize;
        if ml_len > MLDSA65_SIG_LEN {
            return Err(Error::Verify);
        }
        if bytes.len() != 4 + ml_len + 64 {
            return Err(Error::Verify);
        }
        let mldsa_sig = bytes[4..4 + ml_len].to_vec();
        let mut ed25519_sig = [0u8; 64];
        ed25519_sig.copy_from_slice(&bytes[4 + ml_len..]);
        Ok(Self {
            mldsa_sig,
            ed25519_sig,
        })
    }
}

impl HybridDsaVerifyingKey {
    /// Serialise: `u32_be(len_mldsa_vk) || mldsa_vk || ed25519_vk`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.mldsa_vk_bytes.len() as u32;
        let mut out = Vec::with_capacity(4 + self.mldsa_vk_bytes.len() + 32);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.mldsa_vk_bytes);
        out.extend_from_slice(&self.ed25519_vk_bytes);
        out
    }

    /// Deserialise from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 + 32 {
            return Err(Error::InvalidKey);
        }
        let ml_len_bytes: [u8; 4] = bytes[..4].try_into().map_err(|_| Error::InvalidKey)?;
        let ml_len = u32::from_be_bytes(ml_len_bytes) as usize;
        if ml_len > MLDSA65_VK_LEN {
            return Err(Error::InvalidKey);
        }
        if bytes.len() != 4 + ml_len + 32 {
            return Err(Error::InvalidKey);
        }
        let mldsa_vk_bytes = bytes[4..4 + ml_len].to_vec();
        let mut ed25519_vk_bytes = [0u8; 32];
        ed25519_vk_bytes.copy_from_slice(&bytes[4 + ml_len..]);
        Ok(Self {
            mldsa_vk_bytes,
            ed25519_vk_bytes,
        })
    }
}

/// Generate a fresh hybrid keypair.
pub fn hybrid_keygen() -> (HybridDsaSigningKey, HybridDsaVerifyingKey) {
    // ML-DSA-65 (Generate trait uses OsRng internally with getrandom feature)
    let mldsa_sk = MlDsaSigningKey::<MlDsa65>::generate();
    let mldsa_vk = mldsa_sk.verifying_key();
    let mldsa_seed_exported = mldsa_sk.to_bytes(); // KeyExport::to_bytes() → Seed = [u8; 32]
    let mldsa_vk_exported = mldsa_vk.to_bytes(); // KeyExport::to_bytes() → Key<VK>

    // Ed25519
    let ed25519_sk = Ed25519SigningKey::generate(&mut rand_core::OsRng);
    let ed25519_vk = ed25519_sk.verifying_key();

    (
        HybridDsaSigningKey {
            mldsa_seed: Zeroizing::new(AsRef::<[u8]>::as_ref(&mldsa_seed_exported).to_vec()),
            ed25519_seed: Zeroizing::new(ed25519_sk.to_bytes()),
        },
        HybridDsaVerifyingKey {
            mldsa_vk_bytes: AsRef::<[u8]>::as_ref(&mldsa_vk_exported).to_vec(),
            ed25519_vk_bytes: ed25519_vk.to_bytes(),
        },
    )
}

/// Sign `message` with the hybrid signing key.
pub fn hybrid_sign(sk: &HybridDsaSigningKey, message: &[u8]) -> Result<HybridSignature> {
    // Reconstruct ML-DSA-65 signing key from stored 32-byte seed (KeyInit::new_from_slice)
    let mldsa_sk = MlDsaSigningKey::<MlDsa65>::new_from_slice(sk.mldsa_seed.as_slice())
        .map_err(|_| Error::InvalidKey)?;

    // Reconstruct Ed25519 signing key from seed bytes
    let ed25519_sk = Ed25519SigningKey::from_bytes(&sk.ed25519_seed);

    // Sign with ML-DSA-65
    let mldsa_sig = mldsa_sk.sign(message);
    let mldsa_sig_bytes = mldsa_sig.to_bytes(); // SignatureEncoding::to_bytes() → EncodedSignature

    // Sign with Ed25519
    use ed25519_dalek::Signer as _;
    let ed25519_sig = ed25519_sk.sign(message);

    Ok(HybridSignature {
        mldsa_sig: AsRef::<[u8]>::as_ref(&mldsa_sig_bytes).to_vec(),
        ed25519_sig: ed25519_sig.to_bytes(),
    })
}

/// Verify a hybrid signature. Both ML-DSA-65 and Ed25519 must be valid.
pub fn hybrid_verify(
    vk: &HybridDsaVerifyingKey,
    message: &[u8],
    sig: &HybridSignature,
) -> Result<()> {
    // Reconstruct ML-DSA-65 verifying key from stored bytes (KeyInit::new_from_slice)
    let mldsa_vk = MlDsaVerifyingKey::<MlDsa65>::new_from_slice(vk.mldsa_vk_bytes.as_slice())
        .map_err(|_| Error::Verify)?;

    // Reconstruct Ed25519 verifying key
    let ed25519_vk =
        ed25519_dalek::VerifyingKey::from_bytes(&vk.ed25519_vk_bytes).map_err(|_| Error::Verify)?;

    // Verify ML-DSA-65
    let mldsa_sig = ml_dsa::Signature::<MlDsa65>::try_from(sig.mldsa_sig.as_slice())
        .map_err(|_| Error::Verify)?;
    mldsa_vk
        .verify(message, &mldsa_sig)
        .map_err(|_| Error::Verify)?;

    // Verify Ed25519
    let ed25519_sig = Ed25519Signature::from_bytes(&sig.ed25519_sig);
    use ed25519_dalek::Verifier as _;
    ed25519_vk
        .verify(message, &ed25519_sig)
        .map_err(|_| Error::Verify)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let (sk, vk) = hybrid_keygen();
        let msg = b"brigid hybrid DSA test";
        let sig = hybrid_sign(&sk, msg).unwrap();
        assert!(hybrid_verify(&vk, msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let (sk, vk) = hybrid_keygen();
        let sig = hybrid_sign(&sk, b"original").unwrap();
        assert!(hybrid_verify(&vk, b"tampered", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _vk) = hybrid_keygen();
        let (_, vk2) = hybrid_keygen();
        let sig = hybrid_sign(&sk, b"message").unwrap();
        assert!(hybrid_verify(&vk2, b"message", &sig).is_err());
    }

    #[test]
    fn serialization_round_trip() {
        let (sk, vk) = hybrid_keygen();
        let msg = b"round trip test";
        let sig = hybrid_sign(&sk, msg).unwrap();
        let sig_bytes = sig.to_bytes();
        let sig2 = HybridSignature::from_bytes(&sig_bytes).unwrap();
        let vk_bytes = vk.to_bytes();
        let vk2 = HybridDsaVerifyingKey::from_bytes(&vk_bytes).unwrap();
        assert!(hybrid_verify(&vk2, msg, &sig2).is_ok());
    }

    #[test]
    fn truncated_signature_fails() {
        assert!(HybridSignature::from_bytes(&[0u8; 10]).is_err());
    }
}
