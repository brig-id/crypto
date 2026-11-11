//! Known-answer tests for the post-quantum layer of the hybrid wrappers
//! (crypto#3), with vectors from NIST's ACVP server
//! (<https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files>).
//!
//! Only the PQC primitives are checked here, through the same entry points
//! `kem.rs` and `dsa.rs` use (seed-based keys); the X25519 and Ed25519 halves
//! are covered by their own crates' suites. Each `tests/acvp/*.json` file is a
//! small subset of the upstream file it names in `source`.

use ml_dsa::{KeyExport as _, KeyInit as _, Keypair as _, MlDsa65, SigningKey, VerifyingKey};
use ml_kem::{
    B32, DecapsulationKey768, EncapsulationKey768, MlKem768,
    kem::{Decapsulate as _, TryKeyInit as _},
};
use serde::Deserialize;

fn hex(s: &str) -> Vec<u8> {
    helpers4::hex::decode(s).expect("vector hex")
}

fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = format!("{}/tests/acvp/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("vector JSON")
}

// ── ML-KEM-768 (FIPS 203) ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct KemKeyGen {
    tests: Vec<KemKeyGenCase>,
}
#[derive(Deserialize)]
struct KemKeyGenCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    d: String,
    z: String,
    ek: String,
}

/// KeyGen from the 64-byte seed d‖z, which is exactly what the hybrid secret
/// key stores and `hybrid_decapsulate` rebuilds the key from.
#[test]
fn ml_kem_768_keygen_from_seed() {
    let v: KemKeyGen = load("ml-kem-768-keygen.json");
    assert!(!v.tests.is_empty());
    for t in v.tests {
        let seed: Vec<u8> = [hex(&t.d), hex(&t.z)].concat();
        let dk = DecapsulationKey768::from_seed(
            ml_kem::Seed::try_from(seed.as_slice()).expect("64-byte seed"),
        );
        let ek = dk.encapsulation_key().to_bytes();
        assert_eq!(ek.as_slice(), hex(&t.ek), "tcId {}", t.tc_id);
    }
}

#[derive(Deserialize)]
struct KemEncapDecap {
    encapsulation: Vec<KemEncapCase>,
    decapsulation: Vec<KemDecapCase>,
}
#[derive(Deserialize)]
struct KemEncapCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    ek: String,
    m: String,
    c: String,
    k: String,
}
#[derive(Deserialize)]
struct KemDecapCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    dk: String,
    c: String,
    k: String,
}

#[test]
fn ml_kem_768_encapsulate() {
    let v: KemEncapDecap = load("ml-kem-768-encap-decap.json");
    assert!(!v.encapsulation.is_empty());
    for t in v.encapsulation {
        let ek = EncapsulationKey768::new_from_slice(&hex(&t.ek)).expect("valid ek");
        let m = B32::try_from(hex(&t.m).as_slice()).expect("32-byte m");
        let (c, k) = ek.encapsulate_deterministic(&m);
        assert_eq!(c.as_slice(), hex(&t.c), "ciphertext, tcId {}", t.tc_id);
        assert_eq!(k.as_slice(), hex(&t.k), "shared key, tcId {}", t.tc_id);
    }
}

#[test]
#[allow(deprecated)] // ACVP gives the expanded dk, not the seed
fn ml_kem_768_decapsulate() {
    let v: KemEncapDecap = load("ml-kem-768-encap-decap.json");
    assert!(!v.decapsulation.is_empty());
    for t in v.decapsulation {
        let dk_bytes = hex(&t.dk);
        let expanded = ml_kem::ml_kem_768::ExpandedDecapsulationKey::try_from(dk_bytes.as_slice())
            .expect("expanded dk size");
        let dk = DecapsulationKey768::from_expanded(&expanded).expect("valid dk");
        let c = ml_kem::Ciphertext::<MlKem768>::try_from(hex(&t.c).as_slice())
            .expect("ciphertext size");
        let k = dk.decapsulate(&c);
        assert_eq!(k.as_slice(), hex(&t.k), "tcId {}", t.tc_id);
    }
}

// ── ML-DSA-65 (FIPS 204) ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DsaKeyGen {
    tests: Vec<DsaKeyGenCase>,
}
#[derive(Deserialize)]
struct DsaKeyGenCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    seed: String,
    pk: String,
}

/// KeyGen from the 32-byte seed ξ, the form the hybrid signing key stores.
#[test]
fn ml_dsa_65_keygen_from_seed() {
    let v: DsaKeyGen = load("ml-dsa-65-keygen.json");
    assert!(!v.tests.is_empty());
    for t in v.tests {
        let sk = SigningKey::<MlDsa65>::new_from_slice(&hex(&t.seed)).expect("32-byte seed");
        let pk = sk.verifying_key().to_bytes();
        assert_eq!(pk.as_slice(), hex(&t.pk), "tcId {}", t.tc_id);
    }
}

#[derive(Deserialize)]
struct DsaSigVer {
    tests: Vec<DsaSigVerCase>,
}
#[derive(Deserialize)]
struct DsaSigVerCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    pk: String,
    message: String,
    context: String,
    signature: String,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    reason: String,
}

/// External ("pure") ML-DSA verification with a context string: valid
/// signatures verify, and each tampered one (z, hint, commitment) does not.
#[test]
fn ml_dsa_65_verify() {
    let v: DsaSigVer = load("ml-dsa-65-sigver.json");
    assert!(v.tests.iter().any(|t| t.test_passed));
    assert!(v.tests.iter().any(|t| !t.test_passed));
    for t in v.tests {
        let vk = VerifyingKey::<MlDsa65>::new_from_slice(&hex(&t.pk)).expect("valid pk");
        let verified = ml_dsa::Signature::<MlDsa65>::try_from(hex(&t.signature).as_slice())
            .is_ok_and(|sig| vk.verify_with_context(&hex(&t.message), &hex(&t.context), &sig));
        assert_eq!(verified, t.test_passed, "tcId {} ({})", t.tc_id, t.reason);
    }
}
