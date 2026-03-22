# Changelog

## [1.0.0] — 2026-03-21

### Stable Release
- **Archive format frozen at v1.4.** `FORMAT_STABLE` flag (bit 4) set in all v1.0+ archives. Future format changes require v2.0 with new magic bytes.
- **FORMAT.md:** Complete field-level specification of every byte in the archive format.
- **AUDIT.md:** Security audit checklist with findings and mitigations.
- **FUZZING.md:** AFL++ setup, corpus generation, expected coverage targets.
- **License changed:** GPL-3.0 → MIT. All source file headers updated.

## [0.7.0] — 2026-03-21

### Added — Post-Quantum Hybrid Encryption
- **ML-KEM-768 (FIPS 203)** pure C11 implementation in `src/zupt_mlkem.c` (~600 lines). Constant-time NTT, Barrett/Montgomery reduction, CBD sampling, Fujisaki-Okamoto CCA transform with implicit rejection.
- **X25519 (RFC 7748)** pure C11 implementation in `src/zupt_x25519.c` (~270 lines). Montgomery ladder, constant-time `fe_cswap`, 5×51-bit field arithmetic.
- **Keccak-f[1600]** with SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 in `src/zupt_keccak.c` (~215 lines). Required by ML-KEM for hashing and sampling.
- **Hybrid KEM:** ML-KEM-768 + X25519 combined key encapsulation. Shared secret derived via `SHA3-512(ml_kem_ss XOR x25519_ss ‖ ct ‖ ephemeral_pk ‖ "ZUPT-HYBRID-v1")`. Secure if EITHER ML-KEM or X25519 is secure.
- **`zupt keygen`** subcommand generates ML-KEM-768 + X25519 keypair (`.zupt-key` format). `--pub` exports public key only.
- **`--pq <keyfile>`** flag for compress/extract/list/test. Encrypts with recipient's public key (no password needed).
- **Key file format:** `ZKEY` magic, version byte, flags, ML-KEM pk (1184B) + X25519 pk (32B) + optional sk (2400B + 32B), XXH64 checksum.
- **10-test PQ test suite** (`tests/test_pq.sh`): keygen, pubkey export, key sizes, PQ compress, round-trip, integrity, wrong-key rejection, password backward compat, PQ+MT, large file.

### Fixed — ML-KEM Bugs (Critical)
- **basemul array out-of-bounds:** Loop accessed `zetas[64+i]` past the 128-entry array. Fixed to 64 iterations with ±zeta per FIPS 203.
- **Missing `poly_tomont` in keygen:** Public key was computed without Montgomery domain normalization. K-PKE encrypt/decrypt produced different results.
- **Inverted cmov in FO decaps:** Constant-time conditional always selected the rejection key, even on valid ciphertext. Root cause: C integer promotion in `(diff-1) >> 8` expression.
- **`inv_ntt` used wrong zetas table:** Separate `zetas_inv[]` with incorrect values. Fixed to reuse `zetas[]` with k counting 127→0.
- **PQ nonce mismatch:** Encrypt and decrypt independently generated random `base_nonce`. Fixed: nonce stored in encryption header, decrypt reads it back.

### Changed
- Archive format: v1.3 → v1.4.
- Encryption header extended: `enc_type` prefix byte (0x01=PBKDF2, 0x02=PQ-Hybrid).
- Legacy v0.5 archives (no enc_type) still read correctly via fallback detection.
- `ZUPT_FLAG_PQ_HYBRID` (bit 3) added to global_flags.

### Security — No Regressions
- HMAC verified before decryption in every worker (unchanged).
- Constant-time MAC comparison (unchanged).
- Password mode (-p) fully backward compatible.
- All intermediate ML-KEM/X25519 key material wiped with `zupt_secure_wipe()`.

## [0.6.0] — 2026-03-21

### Added
- Multi-threaded compression (`-t <N>`). Batch-parallel pipeline. 14-test MT suite.

## [0.5.1] — 2026-03-21

### Fixed
- 16 bugs: Huffman over-subscription, heap-buffer-overflows, CSPRNG fallback removed, constant-time MAC, LE serialization, write error tracking.

## [0.4.0] — 2026-03-01

### Added
- Byte prediction preprocessor (Zupt-LZHP). Solid mode.

## [0.3.0] — 2026-02-15

### Added
- Zupt-LZH codec: LZ77 + Huffman, 1MB window, near-optimal parsing.

## [0.2.0] — 2026-01-20

### Added
- AES-256-CTR + HMAC-SHA256 encryption. PBKDF2. Directory recursion.

## [0.1.0] — 2026-01-01

### Added
- Initial release. Zupt-LZ codec, `.zupt` format, XXH64 checksums, CLI.
