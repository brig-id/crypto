# Changelog

All notable changes to `brigid-crypto` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed (breaking: formats of the hybrid KEM and signatures)

- The hybrid KEM is **X-Wing** (draft-connolly-cfrg-xwing-kem, RustCrypto
  `x-wing`) instead of a hand-made `HKDF(ss_mlkem || ss_x25519)` that did not
  bind the X25519 keys. The secret key is the 32-byte X-Wing seed (was 96
  bytes); public key and ciphertext keep their sizes; a non-contributory X25519
  share is still refused. Checked against the draft's test vectors.
- The hybrid signature is **composite ML-DSA-65 + Ed25519** of
  draft-ietf-lamps-pq-composite-sigs-19 (id-MLDSA65-Ed25519-SHA512): both halves
  sign `M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)`, so the Ed25519
  half is not a standalone signature of the message, and an application context
  can be bound (`hybrid_sign_with_context`). ML-DSA signs in hedged mode. Keys
  and signatures use the draft's fixed-length serialisations (no length prefix).
  Checked against the draft's test vector.
- Nothing in brig·id uses either yet (audit finding S4).

### Removed

- `x25519-dalek` (X-Wing brings its own), and the internal `hkdf_expand_32`.

- Ed25519 verification is strict (`verify_strict`), in `ed25519::verify` and
  in the Ed25519 half of the hybrid signature: weak public keys and
  non-canonical signatures are rejected.
- `MasterKey::from_env` no longer needs `unsafe`; the bytes of a non-UTF-8
  value are still wiped.
- `Error::HexDecode` now wraps `helpers4::hex::DecodeError` instead of
  `hex::FromHexError` (the `hex` dependency is replaced by `helpers4`). The
  redacted `Debug` output is unchanged.

## [0.1.0] - 2026-09-04

First tagged release, alongside `core`, `server-leaf`, and `app`.

### Added

- `aes` — AES-256-GCM authenticated encryption (`EncryptedBlob`), with a
  fresh random nonce per call.
- `hkdf` — HKDF-SHA3-256 key derivation, with domain separation via the
  HKDF `info` parameter so keys derived for different purposes from the
  same secret can never collide.
- `ed25519` — Ed25519 signing, used for OIDC ID token signatures.
- `kem` — ML-KEM-768 + X25519 hybrid key encapsulation (post-quantum,
  FIPS 203 track).
- `dsa` — ML-DSA-65 + Ed25519 hybrid signatures (post-quantum,
  FIPS 204 track).
- `master_key` — `MasterKey`: the 32-byte root secret, loaded from an
  environment variable or a file, zeroized on drop.
- `fuzz_hkdf_derive` fuzz target, wired into a nightly fuzz CI workflow.

### Fixed

- Zeroize key material read from environment variables and files, and
  intermediate copies (e.g. X25519 secret-key copies, hex-decode buffers)
  that would otherwise linger in memory after use.
- `derive_key`/`hkdf_expand_32` bounds-check requested output length and
  return `Result` instead of panicking on an out-of-range request.
- Error messages for key/ciphertext parsing failures no longer echo the
  invalid input or the environment variable name back to the caller.
- ML-KEM/ML-DSA hybrid operations enforce strict length validation and a
  contributory-key check instead of trusting caller-supplied lengths.

### Security

- All secret material is wrapped in `secrecy::Secret`/`SecretBox` end to
  end — no bare `String`/`Vec<u8>` holding key material outside of a
  zeroizing wrapper.
- No `unwrap()` on any path that handles untrusted input.
