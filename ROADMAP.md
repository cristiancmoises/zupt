# VaptVupt — Roadmap

## Released

| Version | Status | Description |
|---------|--------|-------------|
| v0.1 | ✅ | Initial release — LZ77 compression, `.zupt` format, XXH64 checksums |
| v0.2 | ✅ | AES-256-CTR + HMAC-SHA256 encryption, PBKDF2, directory recursion |
| v0.3 | ✅ | VaptVupt-LZH codec — LZ77 + Huffman, 1MB window, near-optimal parsing |
| v0.4 | ✅ | Byte prediction preprocessor (VaptVupt-LZHP), solid mode |
| v0.5 | ✅ | Security hardening — 16 bug fixes, Huffman codec fix, CSPRNG hardened |
| v0.6 | ✅ | Multi-threaded compression (`-t N`), batch-parallel pipeline |
| v0.7 | ✅ | Post-quantum hybrid encryption (ML-KEM-768 + X25519) |
| v1.0 | ✅ | Stable release — format frozen v1.4, security audit, MIT license |
| v1.1 | ✅ | X25519 formula fix, 13 NIST/RFC test vectors, zero `-Wpedantic` warnings |
| v1.2 | ✅ | CPUID runtime detection (AES-NI, AVX2, SSE4.1, PCLMUL) |
| v1.3 | ✅ | ACSL predicates, Jasmin source files (initial), security review |
| v1.4 | ✅ | All 4 Jasmin `.jazz` files compile on jasminc 2026.03.0 |
| **v1.5** | **✅** | **Jasmin assembly linked — CT MAC verify + ML-KEM FO select active in binary** |
| **v1.5.5** | **✅** | **Build system improvements: man page install rules, verbose mode, multi-arch detection** |
| **v2.0** | **✅** | **VaptVupt 1.1.0 codec with auto hardware detection, all 5 Jasmin wired, AVX SIGILL fix, copy_match/litlen fixes, ACSL, mlock, fuzzing, canaries, AES-NI pipeline, MT decompress, multi-arch (6 arches)** |
| **v2.1** | **✅** | **VaptVupt 1.4.0: cross-block dictionary, context prefetch, faster adaptive window, integration API** |
| **v2.1.1** | **✅** | **Termux/Android build fix, arch-safety guard, Keccak UB fix, no stale .o in tarballs** |
| **v2.1.2** | **✅** | **Full-disk backup/restore with sparse detection, all encryption modes, progress bar, 77 tests** |
| **v2.1.3** | **✅** | **Disk restore rewritten — shared block I/O, fixes checksum mismatch on encrypted/PQ archives** |
| **v2.1.3** | **✅** | **LZHP prediction encoding fix, shared write_enc_header, SOLID flag removed from disk, 78 tests** |
| **v2.1.4** | **✅** | **CodeQL: 4 security fixes — TOCTOU races (fstat on fd), X25519 scalar wipe (volatile), 78 tests** |
| **v2.1.5** | **✅** | **Block-level deduplication (--dedup), XXH64 fingerprint index, DEDUP_REF block type, 81 tests** |
| v2.2.4 | ✅ | Five-finding audit pass: help-format, flaky audit (F-02a), `-Wshadow`, missing-prototype on ML-KEM selftest (now wired as vector 14/14), three `const` cppcheck hints; F-02b (index MAC) opened as deferred |
| v2.2.5 | ✅ | F-06 (high): HMAC verifier silently accepted ~6.35% of single-bit MAC tampers on the Jasmin (x86_64) path. F-07: structural check that block at `index_offset` claims `INDEX` type. F-02b reclassified as resolved (the index IS MAC'd; the verifier was buggy). F-08 (cosmetic-metadata coverage) opened, deferred to v2.3.0. |
| v2.3.0 | ✅ | F-08 closed: archive-integrity-trailer (32B AIT after footer; HMAC-SHA256 over `hdr ‖ ft[0..23]` in encrypted modes, XXH64 best-effort in plaintext). Format v1.4 → v1.5. Backward-compat read path with downgrade warning on legacy v1.4 archives. Exhaustive byte sweep: 86 → 18 undetected positions (all per-block-header trivia, deferred to v2.3.1 as F-09). New `tests/test_f08_topmac.sh` regression. |
| v2.3.1 | ✅ | F-09 closed: per-block frame preface bound into MAC via extended-AAD primitives + strict structural validation of the encryption-header block. Format v1.5 → v1.6. Reaches 100% byte-level tamper detection on encrypted archives — exhaustive sweep on 1827-byte v1.6 PQ-SDK archive: 0/1827 silent accepts. v2.3.0 archives extract unchanged; v2.3.0 cleanly rejects v2.3.1 archives (no silent corruption). |
| v2.4.0 | ✅ | Methodology release. `PROMPT.md` → v2: NEW §3.5 exhaustive byte-sweep mandate after format changes, sprint protocol gains a step, §11 outage table grows four rows for F-06..F-09. Makefile help banner now auto-derived from `include/zupt.h` (closes a recurring banner-drift bug). No source/binary changes; archives byte-identical to v2.3.1. |
| v2.4.1 | ✅ | F-10: password-mode KDF default flipped from PBKDF2-SHA256 to Argon2id (libzuptsdk). PBKDF2 remains available via `--kdf pbkdf2` for v2.4.0-and-older reader compatibility. No format change; v2.4.0 already supports reading Argon2id archives via existing enc_type dispatch. F-11 (auth-fail vs integrity-fail error message UX) opened, deferred. |
| v2.4.2 | ✅ | F-11 closed: wrong-password and tampered-archive error messages collapsed into one uniform `Authentication failed (wrong key, wrong password, or tampered archive)` line. Detailed top-MAC wording moves behind `--verbose`. Plaintext tamper keeps detailed XXH64 wording (no key, no oracle concern). Eliminates a verbal probe-oracle that was leaking which failure cause hit first. No format change. |
| v2.4.3 | ✅ | F-12 closed: encrypted archive comments. Implements the previously-reserved `comment_offset` header field via new block type `ZUPT_BLOCK_COMMENT = 0x05`. Comments are UTF-8, up to 4096 bytes, encrypted using the same per-block AEAD pipeline as data blocks (including F-09 preface AAD). `hdr.comment_offset` is in the AIT-signed region, so pointer tampering → auth-fail. CLI flags `-c` / `--comment` and `--comment-file`. `vaptvupt info` reports presence without decrypting; `vaptvupt x` displays comment after extract. v2.4.2 readers extract v2.4.3 archives byte-exact (they ignore `comment_offset`). Format still v1.6. Exhaustive byte sweep on 1878-byte archive with comment: 0/1878 silent accepts. |
| v2.4.4 | ✅ | Distribution packaging + reproducible source tarball. New `make dist` produces byte-identical `vaptvupt-VERSION.tar.gz`; regression test `tests/test_dist_reproducible.sh` asserts two consecutive runs produce identical sha256. Upstream packaging recipes added at `packaging/aur/PKGBUILD`, `packaging/debian/{control,rules,changelog,copyright,source/format}`, and `packaging/homebrew/vaptvupt.rb`. No source-code changes, no format changes. |
| v2.4.5 | ✅ | Packaging arc completion. New `packaging/rpm/vaptvupt.spec` (Fedora/RHEL/CentOS) and `packaging/nix/flake.nix` (NixOS, x86_64 + aarch64). New `DISTRIBUTION.md` covers all 5 packaging methods with concrete submission flows. New `tests/test_packaging_syntax.sh` (18 assertions, wired into `make test`) enforces cross-recipe version consistency and basic syntax validity. No source-code changes. |
| v2.4.6 | ✅ | CI + threat model. Rewrote `.github/workflows/ci.yml` from 4 jobs to 8 (matrix builds, strict warnings, ASAN, PIE, aarch64, dist-reproducibility, packaging-syntax, tag-triggered release). New `THREAT_MODEL.md` (12 KB) documents what VaptVupt protects against and — explicitly per userPreferences — what it does NOT. Packaging-syntax test expanded 18 → 22. No source-code changes. |
| v2.4.7 | ✅ | Manpage refresh + shell completions. |
| v2.4.8 | ✅ | Distro-safe `make check` target + binary packages. |
| v3.0.0 | ✅ | MAJOR: Zupt → VaptVupt rename, VV codec 2.48.5, GUI binary-discovery fix. |
| v3.0.1 | ✅ | GUI license + version-parsing cleanup. |
| v3.0.2 | ✅ | F-13 closed (usage() string-literal length) + help-text drift cleanup. |
| v3.0.3 | ✅ | Static-analysis cleanup (cppcheck + -Wconversion). |
| v3.1.0 | ✅ | VaptVupt codec 2.48.5 → 2.53.3 + F-14 decode over-copy fix. |
| v3.2.0 | ✅ | SHA-256 hardware acceleration (Intel SHA-NI). |
| v3.3.0 | ✅ | Incremental HMAC-SHA256 (per-block MAC malloc + copy eliminated). |
| v3.4.0 | ✅ | F-15: Argon2id KDF parameter transparency (self-describing header). |
| v3.5.0 | ✅ | Measured constant-time MAC comparison (dudect-style). |
| v3.6.0 | ✅ | NIST SP 800-38A AES-256-CTR vectors + ML-KEM self-test fixes. |
| v3.7.0 | ✅ | ML-KEM decaps comparison routed through the audited CT primitive. |
| **v4.0.0** | **✅ Current** | **Stack integration release. Codec → canonical VaptVupt 2.60.4 (security: fixes high-severity OOB heap write in AVX2 decode on exact-`content_size` buffers; brings CBMC-verified BCJ with auto-detection; ratio gate verified byte-identical on identical inputs). F-16 disclosed and fixed: ≤3.8.0's divergent pre-release BCJ encoder wrote undecodable archives on executable content at L8/L9 — affected archives must be re-created with 4.0.0. New `--pq-box` recipient mode (ZUPT_ENC_PQ_BOX_V1, 0x05) via vendored libpqvaptvupt 0.6.0: ML-KEM-768 + X25519 through HKDF-SHA256 domain-separated combiner, magic-tagged keyfiles, 13/13 adversarial suite, ASan/UBSan clean. SHA-NI finally measured on capable silicon: 5.8× (204→1184 MB/s) — the v3.2.0 [ESTIMATED] is retired. Clang restored to the strict matrix (as(1) for Jasmin output). Wire v1.6 unchanged; 8-mode back-compat matrix byte-exact. 26 suites, test_vectors 16/0.** |
| v3.8.0 | ✅ Shipped | **Consolidated measured benchmarks (documentation-only; no source/crypto/wire change, v1.6 identical to 3.7.0). New BENCHMARKS.md publishes a complete reproducible benchmark set with the test machine + method stated for every table: compression ratio + encode/decode throughput at L9 across 5 fixtures; encode-speed-vs-level trade-off (L1 ≈88 MB/s at 2.55×, L9 ≈1 MB/s at 3.90×); encryption overhead separating the one-time KDF (Argon2id ≈741 ms, PBKDF2 ≈1562 ms) from per-block crypto (≈147 MB/s) and plain throughput (≈944 MB/s); and a head-to-head ratio comparison vs zstd-3/zstd-19 that plainly shows where VaptVupt loses. Previously the only documented benchmarks were codec-ratio numbers dated v3.1.0; the crypto-path data measured across 3.2.0–3.7.0 was never consolidated. SHA-NI speedup explicitly marked [ESTIMATED] (test box has no SHA-NI). README benchmark section re-dated and linked to BENCHMARKS.md. 24/24 suites green, test_vectors 16/0, F-09 0/1827.** |

## Planned

| Version | Status | Description |
|---------|--------|-------------|
| v2.3.0 | ✅ shipped | (see "released" table) |
| v2.3.1 | ✅ shipped | (see "released" table — F-09 closed) |
| v2.1 | 📋 Planned | Homebrew, AUR, Debian, RPM, Nix packages |
| v2.2 | 📋 Planned | Coverity Scan, clang-tidy security checkers, Frama-C Eva analysis |
| v2.3 | 📋 Planned | Silesia corpus benchmarks, performance tuning, NEON ARM64 decode path |
| v3.0 | 🔮 Future | EasyCrypt machine-verified proofs for Jasmin crypto, independent audit |

## Priority Order

```
v1.6  AES-NI wired in          ← closes #1 security gap (table-based AES)
v1.7  X25519 Jasmin wired in   ← all 4 Jasmin functions active
v1.8  ACSL + Frama-C           ← formal memory safety proofs
v1.9  mlock + fuzzing           ← closes remaining hardening gaps
v2.0  Performance               ← 4× AES throughput, parallel decompression
```

## Security Gap Status

| Gap | Severity | Status |
|-----|----------|--------|
| Table-based AES (cache-timing) | High | **✅ Closed v2.0** — AES-NI Jasmin |
| X25519 fe_cswap CT | Low | **✅ Closed v2.0** — Jasmin |
| No mlock() for keys | Medium | **✅ Closed v2.0** |
| No fuzzing | Medium | **✅ Closed v2.0** — AFL++ |
| ACSL unproved | Low | **✅ Closed v2.0** — 19 contracts |
| No independent audit | Medium | Open — target v3.0 |

---

© 2026 Cristian Cezar Moisés — AGPL-3.0-or-later
