#![no_main]
// Fuzz target: feed arbitrary bytes into `aes::decrypt`.
// The function must NEVER panic regardless of input.
use brigid_crypto::aes::{self, EncryptedBlob};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [0u8; 32]; // fixed key — we are testing robustness, not security
    if let Ok(blob) = EncryptedBlob::from_bytes(data) {
        let _ = aes::decrypt(&key, &blob);
    }
});
