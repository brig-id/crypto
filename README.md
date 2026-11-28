# brig·id — crypto

`brigid-crypto`: the cryptographic operations of [brig·id](https://brig.id), in one small
library. It writes no primitive of its own: each module is a thin layer over a
[RustCrypto](https://github.com/RustCrypto) implementation, with the formats, the domain
separation and the handling of secrets that brig·id needs.

It is the first thing an auditor of a brig·id server should read: about 1 400 lines, no
`unsafe` outside its tests (the compiler refuses it), no network, and no file read but the
master key's.

## What is in it

| Module | What it does | Built on | Used by the server today |
| --- | --- | --- | --- |
| [`aes`](src/aes.rs) | Authenticated encryption of one field: AES-256-GCM, a random nonce per encryption | `aes-gcm` | Yes: every stored field that describes a person |
| [`hkdf`](src/hkdf.rs) | Key derivation with domain separation: HKDF-SHA3-256, length-prefixed inputs | `hkdf`, `sha3` | Yes: one key per account, derived from the master key |
| [`master_key`](src/master_key.rs) | The server's 256-bit master key: read from a file or the environment, kept in zeroed memory | `secrecy`, `zeroize` | Yes |
| [`ed25519`](src/ed25519.rs) | Classical signatures, strict verification | `ed25519-dalek` | Not directly: the server signs its tokens through its JWT library |
| [`kem`](src/kem.rs) | Hybrid post-quantum key encapsulation: X-Wing (ML-KEM-768 + X25519, draft-connolly-cfrg-xwing-kem) | `x-wing` | Not yet |
| [`dsa`](src/dsa.rs) | Composite signatures: ML-DSA-65 + Ed25519 (`id-MLDSA65-Ed25519-SHA512`, draft-ietf-lamps-pq-composite-sigs) | `ml-dsa`, `ed25519-dalek` | Not yet |

The two post-quantum modules are ready and tested; the server does not call them yet. What
is planned for them is in [`pqc.md`](https://github.com/brig-id/spec/blob/main/pqc.md) of the
specification.

Secrets are held in `secrecy::SecretBox` or `zeroize::Zeroizing` and zeroed when dropped, and
a `Debug` output never shows one.

## How it is checked

- **Known-answer tests**: NIST ACVP vectors for ML-KEM and ML-DSA
  ([`tests/acvp_kat.rs`](tests/acvp_kat.rs)), the X-Wing draft's vectors
  ([`tests/xwing_kat.rs`](tests/xwing_kat.rs)), the composite signature draft's vectors
  ([`tests/composite_kat.rs`](tests/composite_kat.rs)).
- **Fuzzing**, every day in CI, of what reads bytes from outside
  ([`fuzz/fuzz_targets`](fuzz/fuzz_targets)): decryption, key derivation, decapsulation,
  signature verification.
- **Dependencies**: `cargo audit` and `cargo deny` on every change, with no exception
  ([`deny.toml`](deny.toml)); an SBOM is produced with each change.

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo +nightly fuzz run fuzz_decrypt -- -max_total_time=60
```

A pull request is also tested with [`core`](https://github.com/brig-id/core) and the three
servers before it is merged. The library has no version and no release of its own: a server
follows a commit of `main`.

## Reading further

| Question | Where |
| --- | --- |
| What the server encrypts, with which key, and against whom | [`security-model.md`](https://github.com/brig-id/spec/blob/main/security-model.md) |
| The post-quantum plan | [`pqc.md`](https://github.com/brig-id/spec/blob/main/pqc.md) |
| Rules for a change in this repository | [`AGENTS.md`](AGENTS.md) |
| Reporting a vulnerability | [`SECURITY.md`](SECURITY.md) |

## Licence

[LGPL-3.0-or-later](LICENSE).
