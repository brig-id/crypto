# Changelog

All notable changes to `brigid-crypto` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

First tagged release, targeting `v0.1.0` alongside `core`, `server-leaf`,
and `web`.

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
