#![no_main]
// Fuzz target: feed arbitrary bytes as a HybridSignature into `hybrid_verify`.
// The function must NEVER panic (it must return Err, never panic).
use brigid_crypto::dsa::{self, HybridSignature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (_sk, vk) = dsa::hybrid_keygen();
    if let Ok(sig) = HybridSignature::from_bytes(data) {
        let _ = dsa::hybrid_verify(&vk, b"fuzz message", &sig);
    }
});
