# Security Audit — Zupt v2.1.7

**Date:** April 26, 2026
**Author:** Cristian Cezar Moisés
**Audit type:** Self-audit with formal verification (Jasmin CT proofs, ACSL contracts) and NIST/RFC test vectors
**Status:** No independent third-party audit performed
**License (audit covers):** AGPL-3.0-or-later (Zupt core), GPL-3.0-or-later (VaptVupt codec) — commercial: sac@securityops.co

---

## 1. Cryptographic Test Vector Verification — re-validated on v2.1.7

All primitives re-tested against published reference vectors after the v2.1.7 relicense. Identical results to v2.0.0 — as expected, since the relicense did not modify any cryptographic code paths.

| Primitive | Standard | Vectors | v2.1.7 Status |
|-----------|----------|---------|---------------|
| SHA-256 | FIPS 180-4 | 3 (empty, "abc", 448-bit) | **PASS** |
| HMAC-SHA256 | RFC 4231 | 2 (TC2: "Jefe", TC3: 20×0xAA) | **PASS** |
| SHA3-256 | FIPS 202 | 2 (empty, "abc") | **PASS** |
| SHAKE-128 | FIPS 202 | 1 (empty, 128-bit output) | **PASS** |
| X25519 | RFC 7748 §6.1 | 2 (TV1, TV2) | **PASS** |
| ML-KEM-768 | FIPS 203 | 2 (5-trial roundtrip + implicit rejection) | **PASS** |
| XXH64 | xxHash spec | 1 (empty string, seed=0) | **PASS** |
| **Total** | | **13** | **13/13 PASS** |

Reproduction: `make test-vectors && ./test_vectors`

## 2. Jasmin Constant-Time Verification

| Function | Purpose | v2.1.7 Status |
|----------|---------|---------------|
| `zupt_mac_verify_ct` | HMAC comparison | **✅ Linked, CT-proven** |
| `zupt_ct_select_32` | ML-KEM FO select | **✅ Linked, CT-proven** |
| `zupt_aes256_ctr4` | AES-256 4-block pipeline | **✅ Linked, CT by hardware** |
| `zupt_fe_cswap` | X25519 conditional swap | **⚠ Not yet linked** (limb representation mismatch: 5×u51 vs 4×u64) |
| `zupt_aes256_blk` | AES-256 single-block (AES-NI) | **⚠ Not yet linked** (Jasmin stack offset bug: `[rsp+1]` instead of `[rsp+16]`) |

The two unwired functions remain on the v1.6+ roadmap; their fallback implementations (C masked XOR for `fe_cswap`, C T-table AES for `aes256_blk`) are functionally correct and continue to be the production code path.

## 3. ACSL Formal Annotations

19 security-critical functions annotated with `requires/ensures/assigns` contracts.
Target: `frama-c -wp -wp-rte -wp-model Typed+Cast`

## 4. Security Hardening — current status

| Feature | v2.1.7 Status |
|---------|---------------|
| `mlock()` key protection | **✅ Active** |
| Buffer canaries (keyring) | **✅ Active** |
| Always-decrypt timing mitigation | **✅ Active** |
| AFL++ fuzz harnesses | **✅ Available** (`make fuzz-build`) |
| TOCTOU mitigation (`fstat` on fd, not `stat` on path) | **✅ Active** (since v2.1.4) |
| X25519 scalar wipe via `volatile` | **✅ Active** (since v2.1.4) |
| Password strength warnings | **✅ Active** (since v2.1.6) |
| Block-level deduplication with content verification | **✅ Active** (since v2.1.5) |

## 5. VaptVupt Codec Tests — re-validated on v2.1.7

| Test | v2.1.7 Status |
|------|---------------|
| Roundtrip text mode 0 / 1 / 2 (each 64 KB) | **PASS** (3) |
| Roundtrip binary mode 1 (128 KB) | **PASS** |
| Incompressible fallback to store | **PASS** |
| Empty / small input (3 bytes) | **PASS** (2) |
| `vv_xxh64` ↔ `zupt_xxh64` alias | **PASS** |
| Roundtrip large 2 MB (mode 1) | **PASS** |
| RLE-like data roundtrip | **PASS** |
| `window_log=20` roundtrip | **PASS** |
| **Total** | **11/11 PASS** |

## 6. Test Suite Summary — v2.1.7

| Suite | Tests | v2.1.7 Result | What It Covers |
|-------|-------|---------------|----------------|
| NIST/RFC vectors | 13 | **13/13 PASS** | See §1 |
| VaptVupt unit | 11 | **11/11 PASS** | See §5 |
| Regression | 22 | **22/22 PASS** | All codecs, modes, encryption, edge cases, corruption detection |
| Multi-threaded | 14 | **13/14 PASS** ⚠ | N=1/2/4/8, large files, MT+encryption |
| Post-quantum | 10 | **10/10 PASS** | Keygen, PQ encrypt/decrypt, wrong key, password compat, PQ+MT, 2 MB |
| **Total** | **70** | **69/70 PASS** | |

**The single failing case is `Solid+N=8 (3 mismatches)` — see §11 (newly-recorded known limitation).**

Reproduction: `make test-all`

---

## 7. Memory Safety — re-validated on v2.1.7

| Tool | Command | v2.1.7 Result |
|------|---------|---------------|
| AddressSanitizer (plain) | `./zupt_asan compress` / `extract` | **Zero errors** |
| AddressSanitizer (encrypted, PBKDF2) | `./zupt_asan compress -p` | **Zero errors** |
| AddressSanitizer (PQ hybrid) | `./zupt_asan compress --pq` / `extract --pq` | **Zero errors** |
| AddressSanitizer (multi-threaded N=4) | `./zupt_asan compress -t 4` | **Zero errors** |
| AddressSanitizer (deduplication) | `./zupt_asan compress --dedup` | **Zero errors** |
| UndefinedBehaviorSanitizer | Built with `-fsanitize=address,undefined` | **Zero errors** |

Reproduction:
```bash
make test-asan
./zupt_asan compress /tmp/t.zupt /path/to/data/
./zupt_asan extract -o /tmp/out/ /tmp/t.zupt
./zupt_asan keygen -o /tmp/k.key
./zupt_asan keygen --pub -o /tmp/pub.key -k /tmp/k.key
./zupt_asan compress --pq /tmp/pub.key /tmp/pq.zupt /path/to/data/
./zupt_asan extract --pq /tmp/k.key -o /tmp/pqout/ /tmp/pq.zupt
./zupt_asan compress -t 4 /tmp/mt.zupt /path/to/data/
./zupt_asan compress --dedup /tmp/d.zupt /path/to/data/
```

---

## 8. Compiler Warning Audit

| Compiler | Flags | v2.1.7 Warnings |
|----------|-------|-----------------|
| GCC 13.x | `-Wall -Wextra -O2 -std=c11` | **Zero** |
| GCC 13.x (pedantic) | `-Wall -Wextra -Wpedantic -O2 -std=c11` | **Zero** |

---

## 9. Constant-Time Analysis — unchanged from v2.0.0

| Function | Location | CT Method | Jasmin Verified? | Risk Level |
|----------|----------|-----------|-----------------|------------|
| HMAC comparison | `zupt_crypto.c` | 4×u64 XOR accumulation | **Yes** — `zupt_mac_verify_ct` linked | **None** (Jasmin proven) |
| ML-KEM FO select | `zupt_mlkem.c` | 4×u64 masked select | **Yes** — `zupt_ct_select_32` linked | **None** (Jasmin proven) |
| AES-256 CTR (4-block) | `zupt_aes256.c` (AES-NI dispatch) | Hardware AES-NI + AVX | **Yes** — `zupt_aes256_ctr4` linked | **None** (CT by hardware) |
| ML-KEM NTT butterfly | `zupt_mlkem.c` | Montgomery reduction (branchless) | No | Low |
| ML-KEM CBD sampling | `zupt_mlkem.c` | Bitwise operations only | No | Low |
| X25519 fe_cswap | `zupt_x25519.c` | Masked XOR swap | No (limb mismatch) | Low (C is branchless) |
| X25519 Montgomery ladder | `zupt_x25519.c` | Fixed 255 iterations | No | Low |
| AES-256 encrypt (C fallback) | `zupt_aes256.c` | Table-based S-box | No | **HIGH on shared HW without AES-NI** |
| SHA-256 | `zupt_sha256.c` | Table-based constants | No | Low (not secret-indexed) |
| Keccak-f[1600] | `zupt_keccak.c` | Bitwise XOR/ROT only | No | None |
| Key wipe | `zupt_crypto.c` | `explicit_bzero` / volatile | No | Low |

### Jasmin Assembly Verification

Functions confirmed active in binary via `nm`:
```
T zupt_mac_verify_ct      ← Jasmin assembly, CT proven
T zupt_ct_select_32       ← Jasmin assembly, CT proven
T zupt_aes256_ctr4        ← Jasmin assembly, CT by hardware
```
Assembly generated by `jasminc 2026.03.0`. Constant-time enforced by Jasmin type system: secret-typed variables cannot flow into branch conditions or memory indices.

---

## 10. Bugs Found and Fixed (v0.5.1 → v2.1.7)

| Bug | Severity | Version Fixed | Impact |
|-----|----------|---------------|--------|
| Huffman Kraft-inequality violation | Critical | v0.5.1 | Data corruption on specific inputs |
| Heap-buffer-overflow in LZ match finder | Critical | v0.5.1 | Potential code execution |
| `rand()` CSPRNG fallback | Critical | v0.5.1 | Predictable encryption keys |
| ML-KEM `poly_basemul` OOB | Critical | v1.0.0 | Buffer overread in NTT |
| ML-KEM missing `poly_tomont` | Critical | v1.0.0 | Public key in wrong domain |
| ML-KEM inverted FO `cmov` | Critical | v1.0.0 | Always selected rejection key |
| ML-KEM `inv_ntt` wrong table | High | v1.0.0 | NTT roundtrip failure |
| PQ nonce mismatch | High | v1.0.0 | Encrypt/decrypt used different nonces |
| X25519 `AA + a24*E` formula | High | v1.1.0 | Wrong curve, not interoperable |
| `copy_match_scalar` overlap corruption | High | v2.0.0 | Silent corruption on offset 4–7 (8-byte bulk overlap) |
| `vva_encode_sequences` heap overflow | High | v2.0.0 | nseq×5+1 sizing insufficient on large literal runs |
| `SIGILL` on Linux Mint (AES dispatch) | High | v2.0.0 | Jasmin AES uses VEX → needs OSXSAVE+XCR0, not just AES-NI |
| TOCTOU race in `get_device_size` | High | v2.1.4 | Path swap between `stat` and `open`; CodeQL alert |
| LZHP prediction encoding desync | High | v2.1.3 | Data corruption on structured data |

---

## 11. Known Limitations

| Limitation | Impact | Mitigation | Status |
|------------|--------|------------|--------|
| **Solid mode + multi-threaded archives over ~3 MB** ⚠ NEW | Decompression error "Solid block N decompression failed" on extract. Reproduces on v2.1.6 and v2.1.7 (not introduced by relicense). Compression succeeds; extraction fails on a specific block. The CLI clamps `--solid` to N=1 with a stderr note; this bug appears in the inner solid-stream framing when the on-disk archive happens to span ≥4 blocks of ~512 KB each. | Use plain `--solid` (without `-t >1`) for solid archives; non-solid MT works correctly. Investigation in progress in `zupt_format.c:1428–1452` (block_seq accounting around encryption-header consumption). | **Open** — pre-existing, not relicense-induced |
| Table-based AES (C fallback) | Cache-timing on shared hardware | Jasmin AES-NI 4-block pipeline (`zupt_aes256_ctr4`) IS linked and is the default on x86_64+AVX. Single-block Jasmin (`zupt_aes256_blk`) has stack offset bug. | **Partial** — 4-block path covered |
| Table-based SHA-256 | Theoretical cache-timing | Not used on secret-indexed data | **Accepted** |
| PBKDF2 not quantum-safe | Quantum password brute-force | Use `--pq` mode | **Documented** |
| No fuzzing performed | Undiscovered bugs | AFL++ harnesses available via `make fuzz-build`; not yet executed in production | **Planned** |
| No independent audit | Self-assessed only | Open source under AGPL-3.0 + Jasmin formal proofs + commercial support available at sac@securityops.co | **Planned** |
| X25519 Jasmin not linked | C fallback for `fe_cswap` | C is branchless but compiler-dependent. Limb mismatch (Jasmin: 4×u64, C: 5×u51) is the blocker. | **Open** |

---

## 12. v2.1.7 Relicense + VaptVupt Upgrade — Audit Implications

The v2.1.7 release does two distinct things, both of which were validated separately:

**(A) Relicense from MIT to AGPL-3.0-or-later (Zupt core only).** VaptVupt was already GPL-3.0-or-later in upstream and remains so. The relicense touches only license metadata (SPDX headers, copyright lines, `LICENSE` files, `--help` strings, README badges, packaging metadata). **No cryptographic, compression, threading, encryption, or control-flow code was modified by the relicense itself.**

**(B) Upgrade VaptVupt 2.40.0 → 2.46.1.** The 12 VaptVupt files (`src/vv_*.c`, `src/vaptvupt_api.c`, `include/vaptvupt*.h`, `include/vv_*.h`) were replaced from upstream master at `github.com/cristiancmoises/vaptvupt`. Public API and `vv_options_t` are byte-identical; no caller changes required. Most relevantly, **v2.46.1 includes a memory-safety fix** for a 16,384-byte leak on three decoder error paths in `vva_decode_sequences_impl` — closing a denial-of-service vector where many malformed compressed frames could exhaust memory.

Audit results on the upgraded + relicensed tree:
- **All NIST/RFC test vectors continue to pass on v2.1.7.**
- **All ASAN/UBSAN sweeps continue to be clean on v2.1.7.**
- **The single MT failing case (`Solid+N=8`) is verified pre-existing on v2.1.6** by stashing v2.1.7 changes, rebuilding the v2.1.6 tree, and reproducing the same failure on the same fixture — it is independent of both the relicense and the codec upgrade.

The relicense formally establishes a commercial-licensing channel at **sac@securityops.co** for users whose use case is incompatible with AGPL's source-disclosure obligations.

---

## 13. Reproduction

```bash
# Full validation
make clean && make
make test-all       # NIST vectors + VV unit + regression + threaded + PQ
make test-asan      # AddressSanitizer build
# (run ASAN sweep manually per §7)

# Spot-check the relicense
./zupt --version           # should print: zupt 2.1.7
./zupt 2>&1 | grep -i lic  # should print: License: AGPL-3.0-or-later (commercial: sac@securityops.co)
grep -c "SPDX-License-Identifier" src/*.c src/*.h include/*.h tests/*.c
# (should be > 30, all sources covered)
```

---

© 2026 Cristian Cezar Moisés — AGPL-3.0-or-later
Commercial licensing: sac@securityops.co
