#![no_main]
// Fuzz target: feed arbitrary bytes as a HybridCiphertext into `hybrid_decapsulate`.
// The function must NEVER panic regardless of input (implicit rejection expected).
use brigid_crypto::kem::{self, HYBRID_CT_SIZE, HybridCiphertext};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < HYBRID_CT_SIZE {
        return;
    }
    let ct_bytes: &[u8; HYBRID_CT_SIZE] = data[..HYBRID_CT_SIZE].try_into().unwrap();
    let ct = HybridCiphertext::from_bytes(ct_bytes);
    let (_pk, sk) = kem::hybrid_kem_keygen();
    let _ = kem::hybrid_decapsulate(&sk, &ct);
});
