#![no_main]
// Fuzz target: feed arbitrary bytes as a HybridSignature into `hybrid_verify`.
// The function must NEVER panic (it must return Err, never panic).
//
// The verifying key is generated once per process (via OnceLock) to avoid
// expensive ML-DSA keygen on every iteration and to reduce nondeterminism.
use brigid_crypto::dsa::{self, HybridDsaVerifyingKey, HybridSignature};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static VK: OnceLock<HybridDsaVerifyingKey> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let vk = VK.get_or_init(|| {
        let (_sk, vk) = dsa::hybrid_keygen();
        vk
    });
    if let Ok(sig) = HybridSignature::from_bytes(data) {
        let _ = dsa::hybrid_verify(vk, b"fuzz message", &sig);
    }
});
