# AGENTS.md — brig·id `crypto`

This repository contains the **cryptographic primitives** for brig·id.
It is a pure-Rust library crate with no runtime dependencies on OpenSSL or any C crypto library.

## Language

**All content must be in English** — code, comments, doc-comments, commit messages,
issues, pull requests. No exceptions.

## Scope

- AES-256-GCM encryption / decryption
- HKDF-SHA3-256 key derivation
- Ed25519 signatures (classical)
- ML-KEM-768 + X25519 hybrid KEM (post-quantum, FIPS 203)
- ML-DSA-65 + Ed25519 hybrid signatures (post-quantum, FIPS 204)
- MASTER_KEY loading and validation
- Fuzz targets (`fuzz/`)

## Hard security constraints

These rules are non-negotiable. Every AI agent working in this repo must enforce them.

- **Never store a secret in plaintext** — all sensitive material wrapped in `Secret<T>`.
- **Always zeroize secrets** — use `Zeroize` on drop; `decrypt()` returns `Zeroizing<Vec<u8>>`.
- **No `unwrap()` on crypto error paths** — propagate errors with `?` and typed `Error` enums.
- **No OpenSSL** — pure-Rust RustCrypto crates only.
- **No hardcoded keys or test vectors in non-test code**.
- **`BRIGID_MASTER_KEY` must never appear in logs, panics, or error messages**.
- **`panic = "abort"` in release profile** — prevents stack unwinds from leaking key material.
- **Nonces** — always random 96-bit (AES-GCM), never reused, generated via `rand_core::OsRng`.
- **Domain separation** — HKDF `info` field must be set for every derived key context.
- **VSID must never be derived from an alias** — architectural invariant, must be enforced in tests.

## Algorithms

| Purpose | Algorithm | Standard |
| --- | --- | --- |
| Symmetric encryption | AES-256-GCM | NIST |
| Key derivation | HKDF-SHA3-256 | RFC 5869 |
| Classical signatures | Ed25519 | RFC 8032 |
| PQC KEM | ML-KEM-768 + X25519 (hybrid) | FIPS 203 |
| PQC signatures | ML-DSA-65 + Ed25519 (hybrid) | FIPS 204 |

## Key crates

- `aes-gcm`, `hkdf`, `sha3` — RustCrypto
- `ed25519-dalek`, `x25519-dalek` — Dalek cryptography
- `ml-kem`, `ml-dsa` — RustCrypto PQC
- `zeroize`, `secrecy` — memory safety
- `rand_core`, `getrandom` — CSPRNG

## Commit conventions

Format: `type(scope): <emoji> description`

| Type | Emoji | When |
| --- | --- | --- |
| `feat` | ✨ | New feature |
| `fix` | 🐛 | Bug fix |
| `docs` | 📝 | Documentation only |
| `chore` | 🔧 | Maintenance, config |
| `test` | ✅ | Tests |
| `refactor` | ♻️ | Restructuring, no behaviour change |
| `perf` | ⚡️ | Performance |
| `style` | 🎨 | Formatting only |
| `ci` | 👷 | CI/CD |
| `security` | 🔒 | Security fix or hardening |
| `build` | 📦 | Build system, dependencies |
| `revert` | ⏪ | Reverts a previous commit |

### Allowed scopes

| Scope | Maps to |
| --- | --- |
| `aes` | AES-256-GCM module |
| `hkdf` | HKDF-SHA3-256 module |
| `kem` | ML-KEM-768 + X25519 hybrid KEM |
| `dsa` | ML-DSA-65 + Ed25519 hybrid signatures |
| `hybrid` | Shared hybrid construction helpers |
| `fuzz` | Fuzz targets (`fuzz/`) |
| `ci` | `.github/workflows/` |
| `deps` | Dependency bumps |
| `release` | A release pull request (release-please) |

**Do not use a scope outside this list.** If a new module is added, update this table
and `.vscode/settings.json`.

```text
feat(kem): ✨ add ML-KEM-768 encapsulation
fix(aes): 🐛 reject nonces shorter than 96 bits
test(hkdf): ✅ add domain separation collision test
ci(ci): 👷 add conventional commit check
```

## Releases

Nobody tags by hand. `.github/workflows/release.yml` (release-please, through the
shared workflow of brig-id/.github) keeps a release pull request up to date: the next
version (from the commit types since the last release) and its `CHANGELOG.md` entry.
**Merging that pull request is the release**: the tag `vX.Y.Z` and the GitHub Release
follow, and Renovate proposes the new tag to the core and the servers. So:

- the commit type decides the version: `feat` is a minor, `fix` a patch, a `!` or a
  `BREAKING CHANGE:` footer a minor too while the version is 0.x;
- the commit subject is the changelog line: write it for someone reading the release;
- do not edit `CHANGELOG.md`, `.release-please-manifest.json` or the version in
  `Cargo.toml` by hand.

## Commands

```bash
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo audit
cargo deny check
cargo llvm-cov --summary-only
cargo +nightly fuzz run fuzz_decrypt -- -max_total_time=60
```
