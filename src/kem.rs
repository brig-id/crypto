//! Hybrid post-quantum KEM: **X-Wing** (draft-connolly-cfrg-xwing-kem,
//! ML-KEM-768 + X25519), through RustCrypto's `x-wing` crate.
//!
//! X-Wing's combiner hashes both shared secrets together with the X25519
//! ciphertext and public key, `SHA3-256(ss_M || ss_X || ct_X || pk_X ||
//! label)`, which is what makes the hybrid IND-CCA secure as long as either
//! component is. Decapsulation also refuses a non-contributory X25519 share
//! (a low-order point would make the X25519 half contribute nothing).
//!
//! Sizes:
//! - Encapsulation key: 1216 bytes (ML-KEM-768 1184 + X25519 32)
//! - Decapsulation key:   32 bytes (the X-Wing seed; both component keys are
//!   derived from it)
//! - Ciphertext:        1120 bytes (ML-KEM-768 1088 + X25519 32)
//! - Shared secret:       32 bytes

use secrecy::{ExposeSecret, SecretBox};
use x_wing::{
    Ciphertext, DecapsulationKeyRejectNonContrib, Decapsulator, EncapsulationKey, KeyExport,
    TryDecapsulate, XWingKem,
    kem::{Encapsulate, Kem},
};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const HYBRID_PK_SIZE: usize = x_wing::ENCAPSULATION_KEY_SIZE; // 1216
pub const HYBRID_SK_SIZE: usize = x_wing::DECAPSULATION_KEY_SIZE; //   32
pub const HYBRID_CT_SIZE: usize = 1120;

/// Encapsulation (public) key.
pub struct HybridKemPublicKey {
    bytes: [u8; HYBRID_PK_SIZE],
}

/// Decapsulation (secret) key: the 32-byte X-Wing seed, held in a
/// `SecretBox` (zeroized on drop, no `Debug`/`Clone`).
pub struct HybridKemSecretKey {
    seed: SecretBox<[u8; HYBRID_SK_SIZE]>,
}

/// Ciphertext produced by encapsulation.
pub struct HybridCiphertext {
    bytes: [u8; HYBRID_CT_SIZE],
}

impl HybridKemPublicKey {
    pub fn to_bytes(&self) -> [u8; HYBRID_PK_SIZE] {
        self.bytes
    }

    /// Any 1216 bytes are accepted here; a malformed ML-KEM key is refused
    /// when encapsulating to it.
    pub fn from_bytes(bytes: &[u8; HYBRID_PK_SIZE]) -> Self {
        Self { bytes: *bytes }
    }
}

impl HybridKemSecretKey {
    pub fn to_bytes(&self) -> Zeroizing<[u8; HYBRID_SK_SIZE]> {
        Zeroizing::new(*self.seed.expose_secret())
    }

    pub fn from_bytes(bytes: &Zeroizing<[u8; HYBRID_SK_SIZE]>) -> Self {
        Self {
            seed: SecretBox::new(Box::new(**bytes)),
        }
    }

    /// The encapsulation key that belongs to this decapsulation key.
    pub fn public_key(&self) -> HybridKemPublicKey {
        let dk = DecapsulationKeyRejectNonContrib::from(*self.seed.expose_secret());
        let mut bytes = [0u8; HYBRID_PK_SIZE];
        bytes.copy_from_slice(dk.encapsulation_key().to_bytes().as_ref());
        HybridKemPublicKey { bytes }
    }
}

impl HybridCiphertext {
    pub fn to_bytes(&self) -> [u8; HYBRID_CT_SIZE] {
        self.bytes
    }

    pub fn from_bytes(bytes: &[u8; HYBRID_CT_SIZE]) -> Self {
        Self { bytes: *bytes }
    }
}

/// A fresh key pair from the operating system's random source.
pub fn hybrid_kem_keygen() -> (HybridKemPublicKey, HybridKemSecretKey) {
    let (dk, _ek) = XWingKem::generate_keypair();
    let sk = HybridKemSecretKey {
        seed: SecretBox::new(Box::new(*dk.as_bytes())),
    };
    (sk.public_key(), sk)
}

/// Encapsulate a shared secret to `pk`. Returns `(ciphertext, shared_secret)`.
pub fn hybrid_encapsulate(
    pk: &HybridKemPublicKey,
) -> Result<(HybridCiphertext, Zeroizing<[u8; 32]>)> {
    let ek = EncapsulationKey::try_from(&pk.bytes[..]).map_err(|_| Error::Encapsulate)?;
    let (ct, ss) = ek.encapsulate();
    let mut bytes = [0u8; HYBRID_CT_SIZE];
    bytes.copy_from_slice(ct.as_ref());
    let mut shared = Zeroizing::new([0u8; 32]);
    shared.copy_from_slice(ss.as_ref());
    Ok((HybridCiphertext { bytes }, shared))
}

/// Decapsulate `ct` with `sk`. A ciphertext that does not come from `sk`'s
/// public key gives an unrelated secret (ML-KEM's implicit rejection), not an
/// error; a non-contributory X25519 share is an error.
pub fn hybrid_decapsulate(
    sk: &HybridKemSecretKey,
    ct: &HybridCiphertext,
) -> Result<Zeroizing<[u8; 32]>> {
    let dk = DecapsulationKeyRejectNonContrib::from(*sk.seed.expose_secret());
    let ct = Ciphertext::try_from(&ct.bytes[..]).map_err(|_| Error::Decapsulate)?;
    let ss = dk.try_decapsulate(&ct).map_err(|_| Error::Decapsulate)?;
    let mut shared = Zeroizing::new([0u8; 32]);
    shared.copy_from_slice(ss.as_ref());
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (pk, sk) = hybrid_kem_keygen();
        let (ct, ss_enc) = hybrid_encapsulate(&pk).unwrap();
        let ss_dec = hybrid_decapsulate(&sk, &ct).unwrap();
        assert_eq!(*ss_enc, *ss_dec);
    }

    #[test]
    fn different_ciphertext_yields_different_secret() {
        let (pk, _sk) = hybrid_kem_keygen();
        let (ct1, ss1) = hybrid_encapsulate(&pk).unwrap();
        let (ct2, ss2) = hybrid_encapsulate(&pk).unwrap();
        assert_ne!(ct1.to_bytes(), ct2.to_bytes());
        assert_ne!(*ss1, *ss2);
    }

    #[test]
    fn wrong_sk_yields_different_secret() {
        let (pk, _sk) = hybrid_kem_keygen();
        let (_, sk2) = hybrid_kem_keygen();
        let (ct, ss_enc) = hybrid_encapsulate(&pk).unwrap();
        let ss_dec = hybrid_decapsulate(&sk2, &ct).unwrap();
        assert_ne!(*ss_enc, *ss_dec);
    }

    #[test]
    fn serialization_round_trip() {
        let (pk, sk) = hybrid_kem_keygen();
        let pk2 = HybridKemPublicKey::from_bytes(&pk.to_bytes());
        let sk2 = HybridKemSecretKey::from_bytes(&sk.to_bytes());
        assert_eq!(sk2.public_key().to_bytes(), pk.to_bytes());
        let (ct, ss_enc) = hybrid_encapsulate(&pk2).unwrap();
        let ct2 = HybridCiphertext::from_bytes(&ct.to_bytes());
        let ss_dec = hybrid_decapsulate(&sk2, &ct2).unwrap();
        assert_eq!(*ss_enc, *ss_dec);
    }

    #[test]
    fn a_low_order_x25519_share_is_refused() {
        let (pk, sk) = hybrid_kem_keygen();
        let (ct, _) = hybrid_encapsulate(&pk).unwrap();
        let mut bytes = ct.to_bytes();
        // The X25519 ephemeral key is the last 32 bytes; 0 is a low-order point.
        bytes[HYBRID_CT_SIZE - 32..].fill(0);
        assert!(hybrid_decapsulate(&sk, &HybridCiphertext::from_bytes(&bytes)).is_err());
    }
}
