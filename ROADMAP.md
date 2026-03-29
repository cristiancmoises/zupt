# Zupt — Roadmap

## Released

| Version | Status | Description |
|---------|--------|-------------|
| v0.1 | ✅ | Initial release — LZ77 compression, `.zupt` format, XXH64 checksums |
| v0.2 | ✅ | AES-256-CTR + HMAC-SHA256 encryption, PBKDF2, directory recursion |
| v0.3 | ✅ | Zupt-LZH codec — LZ77 + Huffman, 1MB window, near-optimal parsing |
| v0.4 | ✅ | Byte prediction preprocessor (Zupt-LZHP), solid mode |
| v0.5 | ✅ | Security hardening — 16 bug fixes, Huffman codec fix, CSPRNG hardened |
| v0.6 | ✅ | Multi-threaded compression (`-t N`), batch-parallel pipeline |
| v0.7 | ✅ | Post-quantum hybrid encryption (ML-KEM-768 + X25519) |
| v1.0 | ✅ | Stable release — format frozen v1.4, security audit, MIT license |
| v1.1 | ✅ | X25519 formula fix, 13 NIST/RFC test vectors, zero `-Wpedantic` warnings |
| v1.2 | ✅ | CPUID runtime detection (AES-NI, AVX2, SSE4.1, PCLMUL) |
| v1.3 | ✅ | ACSL predicates, Jasmin source files (initial), security review |
| v1.4 | ✅ | All 4 Jasmin `.jazz` files compile on jasminc 2026.03.0 |
| **v1.5** | **✅ Current** | **Jasmin assembly linked — CT MAC verify + ML-KEM FO select active in binary** |

## Planned

| Version | Status | Description |
|---------|--------|-------------|
| v1.6 | 🔧 Next | Fix Jasmin AES-NI stack offset bug → wire `zupt_aes256_blk` (closes table-AES gap) |
| v1.7 | 📋 Planned | Fix Jasmin X25519 limb layout (5×51 → 4×64 or adapt C) → wire `zupt_fe_cswap` |
| v1.8 | 📋 Planned | ACSL function annotations on all crypto functions, Frama-C WP memory safety proofs |
| v1.9 | 📋 Planned | `mlock()` for key material, AFL++ fuzzing harness, buffer canaries |
| v2.0 | 📋 Planned | AES-NI 4-block pipeline (3.5 GB/s), multi-threaded decompression |
| v2.1 | 📋 Planned | Adaptive compression (skip already-compressed files), file type detection |
| v2.2 | 📋 Planned | Man page, updated PDF build guide, complete security review rewrite |
| v2.3 | 📋 Planned | Homebrew, AUR, Debian, RPM, Nix packages |
| v2.4 | 📋 Planned | GitHub Actions CI/CD — GCC + Clang on Linux/macOS/Windows |
| v2.5 | 📋 Planned | Coverity Scan, clang-tidy security checkers, Frama-C Eva analysis |
| v3.0 | 🔮 Future | EasyCrypt machine-verified proofs for Jasmin crypto, independent audit |

## Priority Order

```
v1.6  AES-NI wired in          ← closes #1 security gap (table-based AES)
v1.7  X25519 Jasmin wired in   ← all 4 Jasmin functions active
v1.8  ACSL + Frama-C           ← formal memory safety proofs
v1.9  mlock + fuzzing           ← closes remaining hardening gaps
v2.0  Performance               ← 4× AES throughput, parallel decompression
```

## Security Gap Closure Timeline

| Gap | Severity | Closes In |
|-----|----------|-----------|
| Table-based AES (cache-timing) | **High** on shared hardware | v1.6 (AES-NI Jasmin) |
| X25519 fe_cswap compiler-dependent CT | Low | v1.7 (Jasmin) |
| No `mlock()` for keys | Medium | v1.9 |
| No fuzzing | Medium | v1.9 |
| ACSL memory safety unproved | Low | v1.8 |
| No independent audit | Medium | v3.0 |

---

© 2026 Cristian Cezar Moisés — MIT License
