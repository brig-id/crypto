#![no_main]
// Fuzz target: feed arbitrary bytes as a HybridCiphertext into `hybrid_decapsulate`.
// The function must NEVER panic regardless of input (implicit rejection expected).
//
// The secret key is generated once per process (via OnceLock) to avoid expensive
// ML-KEM keygen on every iteration and to reduce nondeterminism.
use brigid_crypto::kem::{self, HYBRID_CT_SIZE, HybridCiphertext, HybridKemSecretKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static SK: OnceLock<HybridKemSecretKey> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.len() < HYBRID_CT_SIZE {
        return;
    }
    let Ok(ct_bytes) = data[..HYBRID_CT_SIZE].try_into() else {
        return;
    };
    let ct_bytes: &[u8; HYBRID_CT_SIZE] = ct_bytes;
    let ct = HybridCiphertext::from_bytes(ct_bytes);
    let sk = SK.get_or_init(|| {
        let (_pk, sk) = kem::hybrid_kem_keygen();
        sk
    });
    let _ = kem::hybrid_decapsulate(sk, &ct);
});
