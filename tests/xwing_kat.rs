//! X-Wing through brigid-crypto's KEM API, against the test vectors of
//! draft-connolly-cfrg-xwing-kem (as shipped by RustCrypto's x-wing crate,
//! Apache-2.0 OR MIT): the public key derived from the seed, and the shared
//! secret decapsulated from the vector's ciphertext.

use brigid_crypto::kem::{
    HYBRID_CT_SIZE, HYBRID_SK_SIZE, HybridCiphertext, HybridKemSecretKey, hybrid_decapsulate,
};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Vectors {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    sk: String,
    pk: String,
    ct: String,
    ss: String,
}

fn hex(s: &str) -> Vec<u8> {
    helpers4::hex::decode(s).expect("vector hex")
}

#[test]
fn xwing_known_answers() {
    let path = format!("{}/tests/vectors/xwing.json", env!("CARGO_MANIFEST_DIR"));
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(!v.vectors.is_empty());
    for (i, t) in v.vectors.iter().enumerate() {
        let seed: [u8; HYBRID_SK_SIZE] = hex(&t.sk).try_into().unwrap();
        let sk = HybridKemSecretKey::from_bytes(&Zeroizing::new(seed));
        assert_eq!(
            sk.public_key().to_bytes().to_vec(),
            hex(&t.pk),
            "pk, vector {i}"
        );

        let ct: [u8; HYBRID_CT_SIZE] = hex(&t.ct).try_into().unwrap();
        let ss = hybrid_decapsulate(&sk, &HybridCiphertext::from_bytes(&ct)).unwrap();
        assert_eq!(ss.to_vec(), hex(&t.ss), "shared secret, vector {i}");
    }
}
