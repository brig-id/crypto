//! ML-DSA-65 + Ed25519 composite signatures: id-MLDSA65-Ed25519-SHA512 of
//! draft-ietf-lamps-pq-composite-sigs (revision 19).
//!
//! Both signatures are required to verify: an attacker must break *both*
//! ML-DSA-65 (post-quantum) and Ed25519 (classical) to forge one. Each half
//! signs the composite's message representative `M'`, which binds it to this
//! composite and to the application context.
//!
//! Serialised forms (as in the draft):
//!   signature   `mldsa_sig (3309) || ed25519_sig (64)`        = 3373 bytes
//!   public key  `mldsa_vk (1952)  || ed25519_vk (32)`         = 1984 bytes
//!   private key `mldsa_seed (32)  || ed25519_seed (32)`       =   64 bytes

use ed25519_dalek::{Signature as Ed25519Signature, SigningKey as Ed25519SigningKey};
use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa65, SignatureEncoding,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Byte length of an ML-DSA-65 signature (fixed by the standard).
const MLDSA65_SIG_LEN: usize = 3309;
/// Byte length of an ML-DSA-65 verifying key (fixed by the standard).
const MLDSA65_VK_LEN: usize = 1952;
/// Composite signature: ML-DSA-65 signature then Ed25519 signature.
pub const HYBRID_SIG_LEN: usize = MLDSA65_SIG_LEN + 64; // 3373
/// Composite public key: ML-DSA-65 verifying key then Ed25519 public key.
pub const HYBRID_VK_LEN: usize = MLDSA65_VK_LEN + 32; // 1984

/// `Prefix` of draft-ietf-lamps-pq-composite-sigs: the ASCII bytes of
/// "CompositeAlgorithmSignatures2025".
const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
/// `Label` of id-MLDSA65-Ed25519-SHA512. Also the context passed to ML-DSA.
const LABEL: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// The message representative of the composite:
/// `M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)`.
///
/// Both components sign `M'`, never `M`: the prefix and label bind each half
/// to this composite, so the Ed25519 half is not a valid signature of `M` on
/// its own (no "stripping"), and the context binds the signature to the
/// application's use.
fn message_representative(message: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha512};
    let ctx_len = u8::try_from(ctx.len()).map_err(|_| Error::InvalidContext)?;
    let mut m = Vec::with_capacity(PREFIX.len() + LABEL.len() + 1 + ctx.len() + 64);
    m.extend_from_slice(PREFIX);
    m.extend_from_slice(LABEL);
    m.push(ctx_len);
    m.extend_from_slice(ctx);
    m.extend_from_slice(&Sha512::digest(message));
    Ok(m)
}

/// Hybrid signing (secret) key. Both seeds are wrapped in `secrecy::Secret`
/// per the AGENTS.md hard constraint that "all sensitive material wrapped in
/// `Secret<T>`". `Secret<[u8; 32]>` zeroizes the inner array on drop and
/// blocks accidental `Debug`/`Display`/`Clone` of key material.
pub struct HybridDsaSigningKey {
    /// ML-DSA-65 seed (32 bytes, the preferred compact representation).
    mldsa_seed: SecretBox<[u8; 32]>,
    /// Ed25519 signing key seed (32 bytes).
    ed25519_seed: SecretBox<[u8; 32]>,
}

impl HybridDsaSigningKey {
    /// Serialise as the draft does: `mldsa_seed || ed25519_seed` (64 bytes).
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(self.mldsa_seed.expose_secret());
        out[32..].copy_from_slice(self.ed25519_seed.expose_secret());
        out
    }

    /// Deserialise `mldsa_seed || ed25519_seed`.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut mldsa = Zeroizing::new([0u8; 32]);
        let mut ed = Zeroizing::new([0u8; 32]);
        mldsa.copy_from_slice(&bytes[..32]);
        ed.copy_from_slice(&bytes[32..]);
        Self {
            mldsa_seed: SecretBox::new(Box::new(std::mem::take(&mut *mldsa))),
            ed25519_seed: SecretBox::new(Box::new(std::mem::take(&mut *ed))),
        }
    }
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
    /// Serialise as the draft does: `mldsa_sig || ed25519_sig` (3373 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&self.mldsa_sig);
        out.extend_from_slice(&self.ed25519_sig);
        out
    }

    /// Deserialise `mldsa_sig || ed25519_sig`; any other length is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_SIG_LEN {
            return Err(Error::Verify);
        }
        let mut ed25519_sig = [0u8; 64];
        ed25519_sig.copy_from_slice(&bytes[MLDSA65_SIG_LEN..]);
        Ok(Self {
            mldsa_sig: bytes[..MLDSA65_SIG_LEN].to_vec(),
            ed25519_sig,
        })
    }
}

impl HybridDsaVerifyingKey {
    /// Serialise as the draft does: `mldsa_vk || ed25519_vk` (1984 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_VK_LEN);
        out.extend_from_slice(&self.mldsa_vk_bytes);
        out.extend_from_slice(&self.ed25519_vk_bytes);
        out
    }

    /// Deserialise `mldsa_vk || ed25519_vk`; any other length is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_VK_LEN {
            return Err(Error::InvalidKey);
        }
        let mut ed25519_vk_bytes = [0u8; 32];
        ed25519_vk_bytes.copy_from_slice(&bytes[MLDSA65_VK_LEN..]);
        Ok(Self {
            mldsa_vk_bytes: bytes[..MLDSA65_VK_LEN].to_vec(),
            ed25519_vk_bytes,
        })
    }
}

/// Generate a fresh composite key pair. Both component keys are generated
/// independently, as the draft requires (no key reuse across schemes).
pub fn hybrid_keygen() -> (HybridDsaSigningKey, HybridDsaVerifyingKey) {
    let mldsa_sk = MlDsaSigningKey::<MlDsa65>::generate();
    let mldsa_vk = mldsa_sk.verifying_key();
    let mldsa_seed_exported = mldsa_sk.to_bytes(); // KeyExport::to_bytes() → Seed = [u8; 32]
    let mldsa_vk_exported = mldsa_vk.to_bytes(); // KeyExport::to_bytes() → Key<VK>

    let mut mldsa_seed_buf = Zeroizing::new([0u8; 32]);
    mldsa_seed_buf.copy_from_slice(AsRef::<[u8]>::as_ref(&mldsa_seed_exported));
    let mldsa_seed = SecretBox::new(Box::new(std::mem::take(&mut *mldsa_seed_buf)));

    let ed25519_sk = Ed25519SigningKey::generate(&mut crate::os_rng());
    let ed25519_vk = ed25519_sk.verifying_key();
    let mut ed25519_seed_buf = Zeroizing::new(ed25519_sk.to_bytes());
    let ed25519_seed = SecretBox::new(Box::new(std::mem::take(&mut *ed25519_seed_buf)));

    (
        HybridDsaSigningKey {
            mldsa_seed,
            ed25519_seed,
        },
        HybridDsaVerifyingKey {
            mldsa_vk_bytes: AsRef::<[u8]>::as_ref(&mldsa_vk_exported).to_vec(),
            ed25519_vk_bytes: ed25519_vk.to_bytes(),
        },
    )
}

/// The verifying key of a signing key.
pub fn hybrid_verifying_key(sk: &HybridDsaSigningKey) -> Result<HybridDsaVerifyingKey> {
    let mldsa_sk = MlDsaSigningKey::<MlDsa65>::new_from_slice(sk.mldsa_seed.expose_secret())
        .map_err(|_| Error::InvalidKey)?;
    let mldsa_vk = mldsa_sk.verifying_key().to_bytes();
    let ed25519_vk = Ed25519SigningKey::from_bytes(sk.ed25519_seed.expose_secret()).verifying_key();
    Ok(HybridDsaVerifyingKey {
        mldsa_vk_bytes: AsRef::<[u8]>::as_ref(&mldsa_vk).to_vec(),
        ed25519_vk_bytes: ed25519_vk.to_bytes(),
    })
}

/// Sign `message` with an empty application context. See
/// [`hybrid_sign_with_context`].
pub fn hybrid_sign(sk: &HybridDsaSigningKey, message: &[u8]) -> Result<HybridSignature> {
    hybrid_sign_with_context(sk, message, b"")
}

/// Composite-ML-DSA.Sign of draft-ietf-lamps-pq-composite-sigs for
/// id-MLDSA65-Ed25519-SHA512: both components sign `M'`
/// ([`message_representative`]); ML-DSA-65 with the composite label as its
/// context and in **hedged** mode (fresh randomness, as FIPS 204 recommends),
/// Ed25519 as usual. `ctx` is at most 255 bytes.
pub fn hybrid_sign_with_context(
    sk: &HybridDsaSigningKey,
    message: &[u8],
    ctx: &[u8],
) -> Result<HybridSignature> {
    let m_prime = message_representative(message, ctx)?;

    let mldsa_sk = MlDsaSigningKey::<MlDsa65>::new_from_slice(sk.mldsa_seed.expose_secret())
        .map_err(|_| Error::InvalidKey)?;
    let mldsa_sig = mldsa_sk
        .expanded_key()
        .sign_randomized(&m_prime, LABEL, &mut crate::os_rng())
        .map_err(|_| Error::Sign)?;
    let mldsa_sig_bytes = mldsa_sig.to_bytes();

    use ed25519_dalek::Signer as _;
    let ed25519_sk = Ed25519SigningKey::from_bytes(sk.ed25519_seed.expose_secret());
    let ed25519_sig = ed25519_sk.sign(&m_prime);

    Ok(HybridSignature {
        mldsa_sig: AsRef::<[u8]>::as_ref(&mldsa_sig_bytes).to_vec(),
        ed25519_sig: ed25519_sig.to_bytes(),
    })
}

/// Verify with an empty application context. See
/// [`hybrid_verify_with_context`].
pub fn hybrid_verify(
    vk: &HybridDsaVerifyingKey,
    message: &[u8],
    sig: &HybridSignature,
) -> Result<()> {
    hybrid_verify_with_context(vk, message, sig, b"")
}

/// Composite-ML-DSA.Verify: valid only if **both** component signatures of
/// `M'` are valid (ML-DSA-65 with the composite label as context, Ed25519
/// strict).
pub fn hybrid_verify_with_context(
    vk: &HybridDsaVerifyingKey,
    message: &[u8],
    sig: &HybridSignature,
    ctx: &[u8],
) -> Result<()> {
    let m_prime = message_representative(message, ctx).map_err(|_| Error::Verify)?;

    let mldsa_vk = MlDsaVerifyingKey::<MlDsa65>::new_from_slice(vk.mldsa_vk_bytes.as_slice())
        .map_err(|_| Error::Verify)?;
    let ed25519_vk =
        ed25519_dalek::VerifyingKey::from_bytes(&vk.ed25519_vk_bytes).map_err(|_| Error::Verify)?;

    let mldsa_sig = ml_dsa::Signature::<MlDsa65>::try_from(sig.mldsa_sig.as_slice())
        .map_err(|_| Error::Verify)?;
    if !mldsa_vk.verify_with_context(&m_prime, LABEL, &mldsa_sig) {
        return Err(Error::Verify);
    }

    let ed25519_sig = Ed25519Signature::from_bytes(&sig.ed25519_sig);
    ed25519_vk
        .verify_strict(&m_prime, &ed25519_sig)
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
