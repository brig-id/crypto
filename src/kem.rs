//! ML-KEM-768 + X25519 hybrid KEM (FIPS 203).
//!
//! The shared secret is derived via HKDF-SHA3-256 over the concatenation of
//! both sub-secrets: `SS = HKDF(SS_mlkem || SS_x25519, info = b"brigid-hybrid-kem-v1")`.
//! This ensures that breaking *either* primitive alone is insufficient.
//!
//! Key sizes:
//! - Encapsulation key:  1184 bytes (ML-KEM-768)  +  32 bytes (X25519)  = 1216 bytes
//! - Decapsulation key:    64 bytes (ML-KEM seed)  +  32 bytes (X25519)  =   96 bytes
//! - Ciphertext:         1088 bytes (ML-KEM-768)  +  32 bytes (X25519)  = 1120 bytes
//! - Shared secret:        32 bytes

use ml_kem::{
    DecapsulationKey768, EncapsulationKey768, KeyExport, MlKem768,
    kem::{Decapsulate, Encapsulate, Kem, TryKeyInit},
};
use secrecy::{ExposeSecret, Secret};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::{Error, Result, hkdf::hkdf_expand_32};

const MLKEM_EK_SIZE: usize = 1184;
const MLKEM_SEED_SIZE: usize = 64;
const MLKEM_CT_SIZE: usize = 1088;
const X25519_KEY_SIZE: usize = 32;

pub const HYBRID_PK_SIZE: usize = MLKEM_EK_SIZE + X25519_KEY_SIZE; // 1216
pub const HYBRID_SK_SIZE: usize = MLKEM_SEED_SIZE + X25519_KEY_SIZE; //   96
pub const HYBRID_CT_SIZE: usize = MLKEM_CT_SIZE + X25519_KEY_SIZE; // 1120

/// Hybrid encapsulation (public) key: ML-KEM-768 + X25519.
pub struct HybridKemPublicKey {
    mlkem_ek_bytes: [u8; MLKEM_EK_SIZE],
    x25519_pk: [u8; X25519_KEY_SIZE],
}

/// Hybrid decapsulation (secret) key: ML-KEM-768 seed + X25519 static secret.
///
/// The ML-KEM seed is wrapped in `secrecy::Secret<[u8; 64]>` per the AGENTS.md
/// hard constraint that "all sensitive material wrapped in `Secret<T>`". The
/// X25519 part is stored as `X25519StaticSecret`, which is itself the
/// canonical secret type for that primitive and already implements
/// `ZeroizeOnDrop`; wrapping it in a second `Secret<T>` layer would force a
/// byte-level round-trip on every use and create exactly the transient
/// plaintext copies the wrapping is meant to avoid.
pub struct HybridKemSecretKey {
    mlkem_seed: Secret<[u8; MLKEM_SEED_SIZE]>,
    /// Stored as `X25519StaticSecret` directly so the bytes are never
    /// copied out onto the stack on use (decapsulation borrows `&self`).
    /// `StaticSecret` zeroizes its inner `[u8; 32]` on drop.
    x25519_sk: X25519StaticSecret,
}

/// Hybrid ciphertext: ML-KEM ciphertext + X25519 ephemeral public key.
pub struct HybridCiphertext {
    mlkem_ct_bytes: [u8; MLKEM_CT_SIZE],
    x25519_eph_pk: [u8; X25519_KEY_SIZE],
}

impl HybridKemPublicKey {
    /// Serialise to fixed-size byte array.
    pub fn to_bytes(&self) -> [u8; HYBRID_PK_SIZE] {
        let mut out = [0u8; HYBRID_PK_SIZE];
        out[..MLKEM_EK_SIZE].copy_from_slice(&self.mlkem_ek_bytes);
        out[MLKEM_EK_SIZE..].copy_from_slice(&self.x25519_pk);
        out
    }

    /// Deserialise from a fixed-size byte array.
    pub fn from_bytes(bytes: &[u8; HYBRID_PK_SIZE]) -> Self {
        let mut mlkem_ek_bytes = [0u8; MLKEM_EK_SIZE];
        let mut x25519_pk = [0u8; X25519_KEY_SIZE];
        mlkem_ek_bytes.copy_from_slice(&bytes[..MLKEM_EK_SIZE]);
        x25519_pk.copy_from_slice(&bytes[MLKEM_EK_SIZE..]);
        Self {
            mlkem_ek_bytes,
            x25519_pk,
        }
    }
}

impl HybridKemSecretKey {
    /// Serialise the secret key seed. Keep this zeroized.
    pub fn to_bytes(&self) -> Zeroizing<[u8; HYBRID_SK_SIZE]> {
        let mut out = Zeroizing::new([0u8; HYBRID_SK_SIZE]);
        out[..MLKEM_SEED_SIZE].copy_from_slice(self.mlkem_seed.expose_secret());
        // `to_bytes()` returns a fresh `[u8; 32]` containing the raw X25519
        // scalar; wrap it in `Zeroizing` so the temporary is wiped as soon as
        // this scope ends instead of lingering on the stack/in registers.
        let x25519_bytes: Zeroizing<[u8; X25519_KEY_SIZE]> =
            Zeroizing::new(self.x25519_sk.to_bytes());
        out[MLKEM_SEED_SIZE..].copy_from_slice(&*x25519_bytes);
        out
    }

    /// Deserialise from a secret key seed (zeroized).
    pub fn from_bytes(bytes: &Zeroizing<[u8; HYBRID_SK_SIZE]>) -> Self {
        let mut mlkem_seed_buf = Zeroizing::new([0u8; MLKEM_SEED_SIZE]);
        mlkem_seed_buf.copy_from_slice(&bytes[..MLKEM_SEED_SIZE]);
        // Move the staging buffer into the `Secret` wrapper via `mem::replace`
        // (overwriting with zeros) so the staging slot is zeroed in the same
        // step (no transient duplicate of the seed remains alive). We use
        // `mem::replace` rather than `mem::take` because `Default` is not
        // implemented for `[u8; 64]` in core.
        let mlkem_seed = Secret::new(std::mem::replace(
            &mut *mlkem_seed_buf,
            [0u8; MLKEM_SEED_SIZE],
        ));
        // Copy the X25519 portion into a `Zeroizing` buffer, then `mem::take`
        // it into `X25519StaticSecret::from`. Taking (vs dereferencing) wipes
        // the buffer's content in the same step it hands ownership to
        // `StaticSecret`, so no extra plaintext copy of the scalar exists
        // even transiently.
        let mut x25519_bytes = Zeroizing::new([0u8; X25519_KEY_SIZE]);
        x25519_bytes.copy_from_slice(&bytes[MLKEM_SEED_SIZE..]);
        let x25519_sk = X25519StaticSecret::from(std::mem::take(&mut *x25519_bytes));
        Self {
            mlkem_seed,
            x25519_sk,
        }
    }
}

impl HybridCiphertext {
    /// Serialise to fixed-size byte array.
    pub fn to_bytes(&self) -> [u8; HYBRID_CT_SIZE] {
        let mut out = [0u8; HYBRID_CT_SIZE];
        out[..MLKEM_CT_SIZE].copy_from_slice(&self.mlkem_ct_bytes);
        out[MLKEM_CT_SIZE..].copy_from_slice(&self.x25519_eph_pk);
        out
    }

    /// Deserialise from a fixed-size byte array.
    pub fn from_bytes(bytes: &[u8; HYBRID_CT_SIZE]) -> Self {
        let mut mlkem_ct_bytes = [0u8; MLKEM_CT_SIZE];
        let mut x25519_eph_pk = [0u8; X25519_KEY_SIZE];
        mlkem_ct_bytes.copy_from_slice(&bytes[..MLKEM_CT_SIZE]);
        x25519_eph_pk.copy_from_slice(&bytes[MLKEM_CT_SIZE..]);
        Self {
            mlkem_ct_bytes,
            x25519_eph_pk,
        }
    }
}

/// Generate a fresh hybrid KEM keypair.
pub fn hybrid_kem_keygen() -> (HybridKemPublicKey, HybridKemSecretKey) {
    // ML-KEM-768 (getrandom feature provides entropy internally)
    let (dk, ek) = MlKem768::generate_keypair();
    let ek_exported = ek.to_bytes(); // Key<EK768> = Array<u8, U1184>
    let dk_seed = dk.to_bytes(); // Seed = Array<u8, U64>

    let mut mlkem_ek_bytes = [0u8; MLKEM_EK_SIZE];
    mlkem_ek_bytes.copy_from_slice(ek_exported.as_ref());

    let mut mlkem_seed_buf = Zeroizing::new([0u8; MLKEM_SEED_SIZE]);
    mlkem_seed_buf.copy_from_slice(dk_seed.as_ref());
    let mlkem_seed = Secret::new(std::mem::replace(
        &mut *mlkem_seed_buf,
        [0u8; MLKEM_SEED_SIZE],
    ));

    // X25519 — generate the static secret directly; no intermediate byte
    // buffer is created (would otherwise sit unzeroized on the stack).
    let x25519_sk = X25519StaticSecret::random_from_rng(rand_core::OsRng);
    let x25519_pk_raw = X25519PublicKey::from(&x25519_sk);

    (
        HybridKemPublicKey {
            mlkem_ek_bytes,
            x25519_pk: x25519_pk_raw.to_bytes(),
        },
        HybridKemSecretKey {
            mlkem_seed,
            x25519_sk,
        },
    )
}

/// Encapsulate a shared secret to `pk`. Returns `(ciphertext, shared_secret)`.
pub fn hybrid_encapsulate(
    pk: &HybridKemPublicKey,
) -> Result<(HybridCiphertext, Zeroizing<[u8; 32]>)> {
    // Reconstruct ML-KEM-768 encapsulation key
    let ek: EncapsulationKey768 = EncapsulationKey768::new_from_slice(&pk.mlkem_ek_bytes[..])
        .map_err(|_| Error::Encapsulate)?;

    // ML-KEM encapsulate (infallible; implicit rejection handles invalid inputs)
    let (mlkem_ct, mlkem_ss) = ek.encapsulate();

    let mut mlkem_ct_bytes = [0u8; MLKEM_CT_SIZE];
    mlkem_ct_bytes.copy_from_slice(mlkem_ct.as_ref());

    // X25519 ephemeral DH
    let eph_sk = X25519StaticSecret::random_from_rng(rand_core::OsRng);
    let eph_pk = X25519PublicKey::from(&eph_sk);
    let recipient_pk = X25519PublicKey::from(pk.x25519_pk);
    let x25519_ss = eph_sk.diffie_hellman(&recipient_pk);
    // Reject low-order recipient public keys (would yield an all-zero shared secret
    // and contribute nothing to the hybrid secret).
    if !x25519_ss.was_contributory() {
        return Err(Error::Encapsulate);
    }

    // Combine via HKDF-SHA3-256
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(mlkem_ss.as_ref());
    ikm[32..].copy_from_slice(x25519_ss.as_bytes());
    let shared_secret = hkdf_expand_32(&*ikm, b"brigid-hybrid-kem-v1")?;

    Ok((
        HybridCiphertext {
            mlkem_ct_bytes,
            x25519_eph_pk: eph_pk.to_bytes(),
        },
        shared_secret,
    ))
}

/// Decapsulate `ct` using `sk`. Returns the shared secret.
pub fn hybrid_decapsulate(
    sk: &HybridKemSecretKey,
    ct: &HybridCiphertext,
) -> Result<Zeroizing<[u8; 32]>> {
    // Reconstruct ML-KEM-768 decapsulation key from stored seed
    let seed = ml_kem::Seed::try_from(&sk.mlkem_seed.expose_secret()[..])
        .map_err(|_| Error::Decapsulate)?;
    let dk: DecapsulationKey768 = DecapsulationKey768::from_seed(seed);

    // ML-KEM decapsulate (infallible; implicit rejection)
    let mlkem_ct = ml_kem::Ciphertext::<MlKem768>::try_from(&ct.mlkem_ct_bytes[..])
        .map_err(|_| Error::Decapsulate)?;
    let mlkem_ss = dk.decapsulate(&mlkem_ct);

    // X25519 static DH — borrow the stored `StaticSecret` directly; no copy
    // of the secret bytes ever materialises on the stack.
    let eph_pk = X25519PublicKey::from(ct.x25519_eph_pk);
    let x25519_ss = sk.x25519_sk.diffie_hellman(&eph_pk);
    // Reject low-order ephemeral public keys (would yield an all-zero shared
    // secret, defeating the hybrid construction).
    if !x25519_ss.was_contributory() {
        return Err(Error::Decapsulate);
    }

    // Combine via HKDF-SHA3-256
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(mlkem_ss.as_ref());
    ikm[32..].copy_from_slice(x25519_ss.as_bytes());
    let shared_secret = hkdf_expand_32(&*ikm, b"brigid-hybrid-kem-v1")?;

    Ok(shared_secret)
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
        // Two encapsulations to the same key give different ciphertexts and shared secrets
        assert_ne!(ct1.mlkem_ct_bytes, ct2.mlkem_ct_bytes);
        assert_ne!(*ss1, *ss2);
    }

    #[test]
    fn wrong_sk_yields_different_secret() {
        let (pk, _sk) = hybrid_kem_keygen();
        let (_, sk2) = hybrid_kem_keygen();
        let (ct, ss_enc) = hybrid_encapsulate(&pk).unwrap();
        // ML-KEM is designed to always decapsulate without error; the shared secret
        // will simply differ (implicit rejection).
        let ss_dec = hybrid_decapsulate(&sk2, &ct).unwrap();
        assert_ne!(*ss_enc, *ss_dec);
    }

    #[test]
    fn serialization_round_trip() {
        let (pk, sk) = hybrid_kem_keygen();
        let pk2 = HybridKemPublicKey::from_bytes(&pk.to_bytes());
        let sk2 = HybridKemSecretKey::from_bytes(&sk.to_bytes());
        let (ct, ss_enc) = hybrid_encapsulate(&pk2).unwrap();
        let ss_dec = hybrid_decapsulate(&sk2, &ct).unwrap();
        assert_eq!(*ss_enc, *ss_dec);
    }
}
