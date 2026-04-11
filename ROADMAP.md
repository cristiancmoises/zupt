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
| **v1.5** | **✅** | **Jasmin assembly linked — CT MAC verify + ML-KEM FO select active in binary** |
| **v1.5.5** | **✅** | **Man page install, V=1 verbose, LDFLAGS/PIE, rpmlint, multi-arch Makefile** |
| **v2.0** | **✅** | **VaptVupt 1.1.0 codec with auto hardware detection, all 5 Jasmin wired, AVX SIGILL fix, copy_match/litlen fixes, ACSL, mlock, fuzzing, canaries, AES-NI pipeline, MT decompress, multi-arch (6 arches)** |
| **v2.1** | **✅** | **VaptVupt 1.4.0: cross-block dictionary, context prefetch, faster adaptive window, integration API** |
| **v2.1.1** | **✅** | **Termux/Android build fix, arch-safety guard, Keccak UB fix, no stale .o in tarballs** |
| **v2.1.2** | **✅** | **Full-disk backup/restore with sparse detection, all encryption modes, progress bar, 77 tests** |
| **v2.1.3** | **✅** | **Disk restore rewritten — shared block I/O, fixes checksum mismatch on encrypted/PQ archives** |
| **v2.1.3** | **✅ Current** | **LZHP prediction encoding fix, shared write_enc_header, SOLID flag removed from disk, block device O_SYNC, 78 tests** |

## Planned

| Version | Status | Description |
|---------|--------|-------------|
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

© 2026 Cristian Cezar Moisés — MIT License
