#![no_main]
// Fuzz target: feed arbitrary bytes into `hkdf::derive_user_key`.
// The function must NEVER panic regardless of input.
use brigid_crypto::{hkdf, MasterKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fixed master key (we fuzz the user_id and purpose inputs, not the key).
    // Avoid expect/unwrap in fuzz targets — any panic would hide the real finding.
    let Ok(master) = MasterKey::from_hex(&"00".repeat(32)) else { return };

    // Split input into two segments: user_id and purpose.
    let mid = data.len() / 2;
    let (user_id, purpose) = data.split_at(mid);

    // derive_user_key must not panic under any user_id/purpose inputs.
    let _ = hkdf::derive_user_key(&master, user_id, purpose);
});
