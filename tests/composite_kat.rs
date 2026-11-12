//! Composite ML-DSA-65 + Ed25519 against the test vector of
//! draft-ietf-lamps-pq-composite-sigs-19, Appendix E
//! (tcId id-MLDSA65-Ed25519-SHA512): another implementation's keys and
//! signatures, so the construction of `M'`, the label, the pre-hash and the
//! serialisations all have to match the draft.

use brigid_crypto::dsa::{
    HybridDsaSigningKey, HybridDsaVerifyingKey, HybridSignature, hybrid_sign_with_context,
    hybrid_verify, hybrid_verify_with_context, hybrid_verifying_key,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    m: String,
    ctx: String,
    pk: String,
    sk: String,
    s: String,
    #[serde(rename = "sWithContext")]
    s_with_context: String,
}

fn hex(s: &str) -> Vec<u8> {
    helpers4::hex::decode(s).expect("vector hex")
}

fn vector() -> Vector {
    let path = format!(
        "{}/tests/vectors/composite-mldsa65-ed25519.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn verifies_the_drafts_signatures() {
    let v = vector();
    let vk = HybridDsaVerifyingKey::from_bytes(&hex(&v.pk)).unwrap();
    let m = hex(&v.m);
    let ctx = hex(&v.ctx);

    let s = HybridSignature::from_bytes(&hex(&v.s)).unwrap();
    hybrid_verify(&vk, &m, &s).expect("signature with an empty context");

    let sc = HybridSignature::from_bytes(&hex(&v.s_with_context)).unwrap();
    hybrid_verify_with_context(&vk, &m, &sc, &ctx).expect("signature with a context");

    // Each signature is bound to its context and its message.
    assert!(hybrid_verify(&vk, &m, &sc).is_err());
    assert!(hybrid_verify_with_context(&vk, &m, &s, &ctx).is_err());
    assert!(hybrid_verify(&vk, b"another message", &s).is_err());
}

#[test]
fn rebuilds_the_drafts_public_key_from_its_private_key() {
    let v = vector();
    let sk_bytes: [u8; 64] = hex(&v.sk).try_into().unwrap();
    let sk = HybridDsaSigningKey::from_bytes(&sk_bytes);
    assert_eq!(hybrid_verifying_key(&sk).unwrap().to_bytes(), hex(&v.pk));
    assert_eq!(&*sk.to_bytes(), &sk_bytes);
}

#[test]
fn signs_what_the_draft_verifies_hedged() {
    let v = vector();
    let sk = HybridDsaSigningKey::from_bytes(&hex(&v.sk).try_into().unwrap());
    let vk = HybridDsaVerifyingKey::from_bytes(&hex(&v.pk)).unwrap();
    let m = hex(&v.m);
    let ctx = hex(&v.ctx);
    let a = hybrid_sign_with_context(&sk, &m, &ctx).unwrap();
    let b = hybrid_sign_with_context(&sk, &m, &ctx).unwrap();
    hybrid_verify_with_context(&vk, &m, &a, &ctx).unwrap();
    hybrid_verify_with_context(&vk, &m, &b, &ctx).unwrap();
    // Hedged ML-DSA: fresh randomness, so two signatures of the same message differ.
    assert_ne!(a.to_bytes()[..3309], b.to_bytes()[..3309]);
}

#[test]
fn the_ed25519_half_is_not_a_signature_of_the_message() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let v = vector();
    let pk = hex(&v.pk);
    let ed_vk = VerifyingKey::from_bytes(pk[1952..].try_into().unwrap()).unwrap();
    let s = hex(&v.s);
    let ed_sig = Signature::from_bytes(s[3309..].try_into().unwrap());
    // It signs M', not M: stripping the ML-DSA half leaves nothing usable.
    assert!(ed_vk.verify(&hex(&v.m), &ed_sig).is_err());
}
