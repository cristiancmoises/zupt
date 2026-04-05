# Changelog

All notable changes to Zupt are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [2.0.0] — 2026-04-05

### Added — VaptVupt 1.1.0 Codec Integration
- **VaptVupt codec** integrated as `0x0010` — LZ77 + tANS entropy + AVX2 SIMD decode.
- Three compression modes: Ultra-Fast (greedy), Balanced (lazy + 4-way ANS), Extreme (lazy-2 + order-1 context).
- **Rep-match offset coding** — 3 recent offsets tracked (like zstd), saves 10–15 bits per repeated match.
- **Adaptive window selection** — trial-compresses at wlog=16 vs wlog=20, picks larger window only if ≥3% improvement.
- CLI flags `--vv` / `--vaptvupt` to select VaptVupt codec.
- CLI flag `--lzhp` to explicitly select Zupt-LZHP codec.
- VaptVupt source files with dual MIT + Apache-2.0 headers.
- `vv_xxh64` aliased to `zupt_xxh64` via macro (no duplicate symbol).
- Wired into compress (single-thread, multi-thread, solid) and decompress paths.
- 11 VaptVupt unit tests + 6 regression tests (T13–T18).

### Added — Auto Codec Detection
- **`ZUPT_CODEC_AUTO`** — hardware-aware default codec selection:
  - x86_64 with AVX2: VaptVupt (inline AVX2 SIMD decode, ~2–3 GB/s).
  - aarch64 with NEON: VaptVupt (NEON SIMD decode path).
  - All other architectures: Zupt-LZHP (scalar decoder, no SIMD dependency).
- `zupt_resolve_auto_codec()` checks compile-time flags (`__AVX2__`, `__ARM_NEON`) and runtime CPUID.
- Decompression is universal — any archive extracts on any architecture regardless of codec.
- Users can override with `--vv` (force VaptVupt) or `--lzhp` (force LZHP).

### Fixed — Jasmin Assembly
- **AES-NI stack offset bug** fixed: replaced `stack u128[15]` with 15 individual `stack u128` variables to avoid jasminc byte-offset indexing. Round keys now at correct 16-byte aligned offsets.
- **X25519 fe_cswap** wired: Jasmin swaps first 4 limbs (32 bytes), C handles 5th limb.
- **All 5 Jasmin functions now active**: `zupt_mac_verify_ct`, `zupt_ct_select_32`, `zupt_fe_cswap`, `zupt_aes256_blk`, `zupt_aes256_ctr4`.
- **SIGILL fix: AVX detection with OSXSAVE/XCR0 check.** The Jasmin AES assembly uses VEX-encoded instructions (`vaesenc`, `vmovdqu`, `vpxor`) which require AVX — not just AES-NI. Previous dispatch only checked `has_aesni`, causing SIGILL on CPUs with AES-NI but without AVX or without OS XSAVE support. Now checks `has_aesni && has_avx` with proper XGETBV XCR0 validation.
- Added `has_avx` field to `zupt_cpu_features_t` with correct detection: CPUID ECX[28] (AVX) + ECX[27] (OSXSAVE) + XCR0 bits 1+2.

### Fixed — VaptVupt Codec Bugs
- **`copy_match_scalar` overlap corruption** (`vv_simd.c`): 8-byte bulk copy was used for offsets 4–7, where source overlaps destination by more than the copy stride. The `memcpy` read-then-write semantics don't correctly replicate the overlapping pattern. Fix: byte-by-byte for offsets < 8 (was < 4). This caused silent data corruption on inputs with short-offset matches near the output buffer tail.
- **`vva_encode_sequences` heap overflow** (`vv_ans.c`): litlen varint buffer allocated as `nseq * 5 + 1` bytes, but individual literal lengths in solid mode can reach 1 MB, requiring up to `ceil(litlen/255) + 1` bytes per varint. Fix: compute exact bound from actual litlen values. This caused heap corruption and abort (`malloc(): invalid size`) on large solid-mode archives.

### Added — ACSL Formal Annotations
- 19 security-critical functions annotated with complete `requires/ensures/assigns` ACSL contracts.
- Covers: SHA-256, HMAC, PBKDF2, AES-256-CTR, key derivation, encrypt/decrypt, hybrid KEM, SHA3, SHAKE, ML-KEM-768, X25519, secure_wipe.
- Target: `frama-c -wp -wp-rte -wp-model Typed+Cast`.

### Added — Security Hardening
- **mlock()** for key material — prevents swap to disk (Linux/BSD/Windows).
- **Buffer canaries** on `zupt_keyring_t` — `canary_head`/`canary_tail` detect overflow, abort on corruption.
- **Always-decrypt timing mitigation** — `zupt_decrypt_buffer()` always decrypts even on MAC failure (then wipes), preventing timing oracle.
- **AFL++ fuzzing harnesses** — `fuzz_decompress.c` (archive format) and `fuzz_vv_decompress.c` (VaptVupt codec). `make fuzz-build`.

### Added — Performance
- **AES-NI 4-block pipeline** — `zupt_aes256_ctr4` interleaves 4 counter blocks per AES round for pipeline saturation.
- **Multi-threaded decompression** — non-solid extract dispatches blocks to N worker threads via `zpar_ctx_t` infrastructure.
- **Adaptive compression** — `zupt_detect_filetype()` identifies 16+ file formats by magic bytes; already-compressed files get STORE.
- **Benchmark harness** — `zupt bench --compare` tests all codecs + auto-detects gzip/lz4/zstd.

### Changed — Multi-Architecture Support
- **Makefile rewritten** for full multi-arch builds: x86_64, aarch64, armhf, ppc64le, s390x, riscv64.
- Jasmin CT assembly: x86_64 only (C fallback on all others).
- AVX2 SIMD decode: x86_64 only. NEON decode: aarch64. Scalar fallback: everywhere.
- `LDFLAGS` honored on link line for PIE linking (`-pie -Wl,-z,relro,-z,now`).
- `LDLIBS` placed after objects (correct rpmlint/OBS link order).
- `DESTDIR` support for staged packaging installs.
- Man page `doc/zupt.1` compressed and installed to `$(MANDIR)/man1/zupt.1.gz`.
- Verbose build with `make V=1`.
- `make help` shows available targets and detected architecture capabilities.
- AVX2 detection gates `has_avx2` on `has_avx` (OS XSAVE must be enabled).

### Tests
- **70 tests total:** 11 VV unit + 13 NIST/RFC vectors + 22 regression + 14 multi-threaded + 10 post-quantum.
- ASAN clean across all modes (normal, encrypted, solid, threaded, PQ).
- All 5 Jasmin symbols linked (confirmed via `nm`).

---

## [1.5.5] — 2026-04-01

### Fixed — Makefile & Packaging
- Added man page installation (`doc/zupt.1` → `zupt.1.gz` in `$(MAN1DIR)`).
- Enabled verbose build output with `V=1` support.
- Fixed Makefile to honor `LDFLAGS` and support PIE linking.
- Improved rpmlint compliance for OBS/openSUSE packaging.
- Jasmin assembly gated to x86_64 only (`ifeq ($(ARCH),x86_64)`) — clean build on aarch64/armhf/ppc64le.
- Object files excluded from distribution tarballs.
- `install.sh` convenience installer restored.

---

## [1.5.0] — 2026-03-28

### Added — Jasmin Assembly Integration (Sprint 1)
- **`zupt_mac_verify_ct`** Jasmin assembly linked into `zupt_decrypt_buffer()`. Replaces the C XOR accumulation loop for HMAC-SHA256 comparison. 4×u64 unrolled XOR, proven constant-time by Jasmin type system. Symbol confirmed active via `nm`: `T zupt_mac_verify_ct`.
- **`zupt_ct_select_32`** Jasmin assembly linked into `zupt_mlkem768_decaps()`. Replaces the C `cmov()` function for Fujisaki-Okamoto implicit rejection key selection. 4×u64 masked select, proven constant-time. Symbol confirmed active via `nm`: `T zupt_ct_select_32`.
- **`include/zupt_jasmin.h`** — extern declarations for all Jasmin functions with ABI documentation.
- **`#ifdef ZUPT_USE_JASMIN`** dispatch guards in `zupt_crypto.c` and `zupt_mlkem.c` with clean C fallback.
- **Makefile** auto-detects `jasmin/*.s` files, assembles to `.o`, links into binary, sets `-DZUPT_USE_JASMIN`.

### Not Wired (documented, requires upstream fixes)
- `zupt_fe_cswap` (X25519): Jasmin uses 4×u64 limbs, C uses 5×u51-bit — incompatible layout. C fallback active.
- `zupt_aes256_blk` (AES-NI): Assembly has stack offset bug (`[rsp+1]` instead of `[rsp+16]`). C table-based AES active.

### Changed
- Version: 1.4.0 → 1.5.0.
- `cmov()` in `zupt_mlkem.c` guarded with `#ifndef ZUPT_USE_JASMIN`.
- MAC comparison return type widened from `uint8_t` to `uint64_t` to match Jasmin signature.

### Security
- 53/53 tests pass with Jasmin linked. 13/13 NIST vectors. ASAN clean. Zero warnings.

---

## [1.4.0] — 2026-03-28

### Fixed — Jasmin Parse Errors (jasminc 2026.03.0)
All 4 `.jazz` files rewritten to fix compilation errors:

- **`zupt_mac_verify.jazz`**: `diff |= a ^ b` — compound XOR+OR not a single x86-64 op. Split into `tmp = a; tmp ^= b; diff |= tmp`.
- **`zupt_mlkem_select.jazz`**: `out.[i] = (8u)sel` — `reg ptr` is read-only. Changed to `reg u64 out_ptr` with raw pointer writes.
- **`zupt_x25519_fe.jazz`**: `a.[i] = ta ^ diff` — same const-ptr write. Changed to `reg u64 a_ptr`.
- **`zupt_aes_ctr.jazz`**: Memory syntax `(u128)[ptr]` → `u128[ptr]` → `[ptr]` — all wrong. Correct: `key.[0]` via `reg ptr u128[N]` for reads; `stack u128[15]` for writes; bare `[ptr + 0]` for u64-width.
- Uninitialized variable warning: `#VPXOR(zero, zero)` → `wipe = rk.[z]; wipe ^= wipe; rk.[z] = wipe`.

### Changed
- Removed all `-CT` flag references (does not exist in jasminc 2026.03.0).
- CT enforced by Jasmin type system during normal compilation.
- Safety: `jasminc -arch x86-64 -checksafety`.
- All compound expressions split into separate register operations.
- All output parameters changed from `reg ptr` to `reg u64` raw pointers.
- Byte-level access avoided: 4×u64 instead of 32×u8.

---

## [1.3.0] — 2026-03-28

### Added
- `include/zupt_acsl.h` — ACSL predicates: `ValidBuffer`, `ValidWriteBuffer`, `Separated2`, `KeyWiped`, `ValidKey`.
- `SECURITY_REVIEW.md` — 8-section security review with per-function CT analysis table.
- `jasmin/README.jazz.md` — build instructions, CT verification explanation, error history.

### Fixed
- First round of Jasmin syntax fixes (partial — completed in v1.4.0).

---

## [1.2.0] — 2026-03-28

### Added — CPUID Runtime Detection
- **`src/zupt_cpuid.c`** + **`include/zupt_cpuid.h`** — runtime detection of AES-NI, PCLMUL, AVX2, SSE4.1 via CPUID. Supports GCC/Clang, MSVC, and inline assembly fallback.
- `zupt_detect_cpu()` called at program start. Global `zupt_cpu` struct for dispatch.

### Added — Jasmin Source Files (initial)
- 4 `.jazz` files created for AES-CTR, MAC verify, X25519, ML-KEM select.
- **Note:** All had parse errors — fixed in v1.3.0–v1.4.0.

---

## [1.1.0] — 2026-03-28

### Fixed — Critical Cryptographic Bugs

- **X25519 Montgomery formula** (`zupt_x25519.c`): `AA + 121666*E` → `BB + 121666*E`. The doubling formula was algebraically wrong. DH exchanges produced consistently wrong but matching values, so PQ archives worked. RFC 7748 test vectors exposed the bug. **All X25519 in v0.7.0–v1.0.0 was not interoperable with any other implementation.**
- **Dead `match_cost()`** (`zupt_lzh.c`): Defined but never called. Removed (Clang `-Wunused-function`).
- **ML-KEM `const polyvec`** warnings: C11 doesn't support multi-level const for arrays-of-arrays. Removed `const` (matches pqcrystals reference).
- **`__int128` pedantic** warning: Wrapped with `#pragma GCC diagnostic push/pop`.

### Added
- **`tests/test_vectors.c`** — 13 NIST/RFC test vectors: SHA-256 (3), HMAC-SHA256 (2), SHA3-256 (2), SHAKE-128 (1), X25519 (2), ML-KEM-768 (2), XXH64 (1).

### Changed
- Zero warnings on GCC + Clang with `-Wall -Wextra -Wpedantic`.

---

## [1.0.0] — 2026-03-21

### Stable Release
- **Archive format frozen at v1.4.** `FORMAT_STABLE` flag set. Future changes require v2.0.
- Documentation: FORMAT.md, AUDIT.md, FUZZING.md, SECURITY.md.
- **License: GPL-3.0 → MIT.**

### Fixed — ML-KEM-768 Bugs (5 critical)
1. **`poly_basemul` OOB**: `zetas[64+i]` accessed past 128-entry array. Fixed to 64 iterations.
2. **Missing `poly_tomont()` in keygen**: Public key in wrong Montgomery domain.
3. **Inverted `cmov` in FO decaps**: C integer promotion caused rejection key selected on valid ciphertext. Fixed: `(-(int64_t)diff) >> 63`.
4. **`inv_ntt` wrong zetas table**: Separate wrong table. Fixed: reuse `zetas[]`, k counts 127→0.
5. **PQ nonce mismatch**: Encrypt/decrypt independently generated nonces. Fixed: store in header.

### Added — Post-Quantum Hybrid Encryption (v0.7.0)
- **ML-KEM-768** (FIPS 203): ~658 lines pure C11. NTT, Barrett/Montgomery, CBD, FO transform.
- **X25519** (RFC 7748): ~270 lines. Montgomery ladder, constant-time fe_cswap.
- **Keccak-f[1600]**: SHA3-256/512, SHAKE-128/256. ~215 lines.
- **Hybrid KEM**: `SHA3-512(ml_ss XOR x25519_ss ‖ transcript)`. Secure if EITHER holds.
- `zupt keygen` subcommand, `--pq <keyfile>` flag.
- Key file format: ZKEY magic, ML-KEM pk(1184B) + X25519 pk(32B) + optional sk + XXH64.
- 10-test PQ suite.
- Format v1.3 → v1.4 with `enc_type` dispatch byte.

### Added — Multi-Threaded Compression (v0.6.0)
- `-t <N>` flag. Batch-parallel pipeline. 14-test MT suite.
- Solid mode falls back to N=1 (shared LZ context).

### Added — Security Hardening (v0.5.1)
- 16 bug fixes: Huffman Kraft violation (data corruption), heap-buffer-overflows, removed `rand()` fallback, constant-time MAC, secure key wipe, LE serialization, realloc checks, empty file checksum.

### Core Features (v0.1.0–v0.4.0)
- LZ77+Huffman compression (1MB window, near-optimal parsing).
- AES-256-CTR + HMAC-SHA256 authenticated encryption.
- PBKDF2-SHA256 (600,000 iterations).
- Per-block XXH64 integrity. Recursive directory backup. Solid mode.

---

## Summary

| Version | Key Change | Tests |
|---------|-----------|-------|
| **2.0.0** | VaptVupt 1.1.0 codec, auto codec detection, all 5 Jasmin wired, AVX SIGILL fix, multi-arch, copy_match fix, litlen overflow fix | 70 PASS |
| **1.5.5** | Man page install, V=1 verbose, LDFLAGS/PIE, rpmlint, multi-arch Makefile | 53+13 PASS |
| **1.5.0** | Jasmin assembly linked: MAC verify + ML-KEM select active in binary | 53+13 PASS |
| **1.4.0** | All 4 `.jazz` files compile on jasminc 2026.03.0 | 53+13 PASS |
| **1.3.0** | ACSL predicates, security review, partial Jasmin fixes | 53+13 PASS |
| **1.2.0** | CPUID detection, Jasmin source files (with errors) | 53+13 PASS |
| **1.1.0** | X25519 BB formula fix, 13 NIST/RFC test vectors | 53+13 PASS |
| **1.0.0** | Format frozen v1.4, ML-KEM bugs fixed, MIT license | 40 PASS |

---

© 2026 Cristian Cezar Moisés — MIT License
