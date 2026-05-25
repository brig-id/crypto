//! brigid-crypto: cryptographic primitives for brig·id.
//!
//! All sensitive types are wrapped in `secrecy::Secret` or `zeroize::Zeroizing`
//! and zeroed on drop. No `unwrap()` on error paths.

pub mod aes;
pub mod dsa;
pub mod ed25519;
pub mod error;
pub mod hkdf;
pub mod kem;
pub mod master_key;

pub use error::{Error, Result};
pub use master_key::MasterKey;
pub use aes::EncryptedBlob;
pub use kem::{HybridCiphertext, HybridKemPublicKey, HybridKemSecretKey};
pub use dsa::{HybridDsaSigningKey, HybridDsaVerifyingKey, HybridSignature};
