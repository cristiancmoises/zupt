<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# VaptVupt — Security Audit

This document records the security review of VaptVupt: what is checked, how, the
findings and their resolutions, and how to reproduce the checks. It complements
[SECURITY.md](SECURITY.md) (policy + primitives) and
[THREAT_MODEL.md](THREAT_MODEL.md) (what is and isn't defended).

Scope: the pure-C11 CLI (`src/`, `include/`) and the PySide6/PyQt6 GUI
(`gui/src/zupt_gui.py`). Out of scope: the optional, separately distributed
`libzuptsdk` / `libpqvaptvupt` binaries (only present in a `make WITH_SDK=1`
build); the shipped source-only build contains no vendored binaries.

> **Not independently certified.** This is the project's own structured review,
> not a third-party accredited audit. Treat it as "reviewed, with reproducible
> evidence" and do your own review for high-assurance use.

## Methodology

| Technique | What it covers | Where |
|---|---|---|
| **Cryptographic conformance vs an independent reference** | ML-KEM-768 is validated byte-for-byte against **OpenSSL 3.5's FIPS 203 ML-KEM-768** — deterministic keygen `ek` equality plus shared-secret agreement in both cross-decapsulation directions. | `tests/test_mlkem_fips203.sh`, in `make check` |
| **NIST/RFC known-answer vectors** | SHA-256 (FIPS 180-4), SHA-3/SHAKE (FIPS 202), AES-256-CTR (SP 800-38A F.5.5/F.5.6), HMAC-SHA256 (RFC 4231), X25519 (RFC 7748), ML-KEM-768, PBKDF2. | `tests/test_vectors.c` |
| **Byte-level tamper sweep** | Every byte position of a representative archive is flipped and re-opened; zero silent-accepts required (F-09). | `tests/` byte-sweep |
| **Authenticated-encryption fuzzing** | HMAC / integrity-trailer fuzz over many trials (F-06, F-08). | `tests/` |
| **Constant-time measurement** | dudect-style Welch t-test on the MAC-tag compare and the ML-KEM FO implicit-rejection compare (the two decapsulation-oracle-sensitive paths). | `tests/test_ct_timing.*` |
| **Memory-safety sanitizers** | ASan + UBSan builds; exact-size decode cases; crafted-input decode. | `make test-asan` |
| **Static analysis** | cppcheck (warning/style/performance) on the first-party sources; strict `-Wall -Wextra -Wpedantic -Werror` gcc + clang matrix. | CI |
| **Formal annotations** | Frama-C/ACSL contracts on memory-safety-critical functions; 5 Jasmin-verified constant-time assembly routines (x86_64). | `include/zupt_acsl.h`, `jasmin/` |
| **Adversarial multi-agent review** | Independent reviewers per dimension (crypto, parser/memory-safety, CLI, GUI↔CLI contract, packaging), each finding then adversarially refuted before it is accepted. | manual, per release |

## Cryptographic conformance

- **ML-KEM-768 — genuine FIPS 203 (v5.0.0).** Earlier releases shipped round-3
  CRYSTALS-Kyber under a "FIPS 203" label; it was self-consistent and secure as
  an IND-CCA2 KEM but **not interoperable** with a compliant ML-KEM. Validating
  against OpenSSL 3.5 revealed three deviations — a transposed matrix-`Â`
  sampling convention (in both K-PKE.KeyGen and K-PKE.Encrypt), the round-3 final
  KDF, and the implicit-rejection domain. All three were fixed and the result is
  now byte-for-byte interoperable with OpenSSL in both directions. A permanent
  conformance test guards against regression. This changed the shared secret, so
  it is a wire-breaking change for `--pq`/`--pq-only` archives (see CHANGELOG
  5.0.0 BREAKING).
- **Hybrid is the flagship.** `--pq` combines ML-KEM-768 with X25519 through a
  SHA3-512 combiner; the archive key is secure if **either** primitive holds —
  the strongest real-world posture and the recommended default. `--pq-only`
  offers pure ML-KEM-768 for single-primitive compliance mandates.
- **Envelope.** AES-256-CTR with a **fresh random 128-bit nonce per block**
  (the dedup keystream-reuse bug is fixed and regression-tested), HMAC-SHA256
  Encrypt-then-MAC verified before any decryption, and an archive-integrity
  trailer over the header/footer.

## Notable findings and resolutions (recent)

| Sev | Finding | Resolution |
|---|---|---|
| High | ML-KEM-768 not FIPS 203-conformant / not interoperable | Fixed (transpose + KDF); validated vs OpenSSL; permanent conformance test |
| High | `compress -p out.zupt f1 f2` overwrote an input file (data loss, exit 0) | Refuse to overwrite an existing non-`.zupt` output without `-y/--force`; self-overwrite guard |
| High | `compress out.zupt dir -p pw` wrote an **unencrypted** archive (exit 0) | Error on a misplaced option after the archive (`--` escape available) |
| Critical | AES-CTR keystream reuse across `--dedup` blocks (many-time-pad) | Fresh random per-block nonce; regression test |
| Medium | Heap OOB read in the AVX2 decoder fast path on crafted input | Bound the 2-/3-byte offset read like the scalar tail path |
| Medium | GUI defaulted to SDK modes absent from the source-only build (unusable) | Reworked to native `--pq`/`--pq-only`; SDK shown only when supported |
| Low | Hybrid-decrypt did not wipe secret buffers on key-read failure | Wipe on the error path (matches the pq-only path) |
| Low | Untruthful banner (Argon2id-default / `/zupt` URL) on source-only builds | Build-aware, accurate `version`/`help` output |
| Critical* | Packaging (`debian/rules`, `aur`, `nix`, `homebrew`, `opensuse`) would fail a source-only build | Removed vendored-lib/`AUDIT.md` steps, fixed URLs, added completions |

\* build-time failure, not a runtime security issue.

## Known limitations / non-goals

- No protection against a compromised endpoint, a weak password, or key
  custody failures (see THREAT_MODEL.md).
- Metadata (total archive size, block count) is observable.
- The review is reproducible but not third-party certified.

## Reproducing

```sh
make check                 # vectors, tamper sweep, FIPS 203 conformance, guards
make test-asan             # ASan + UBSan
bash tests/test_mlkem_fips203.sh   # FIPS 203 interop vs OpenSSL (needs openssl 3.5+)
```

FIPS 203 conformance needs an ML-KEM-capable OpenSSL (3.5+); the test skips
gracefully otherwise (e.g. inside a distro package build).
