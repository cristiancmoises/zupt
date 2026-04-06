<img width="493" height="173" alt="logo" src="https://github.com/user-attachments/assets/164f5217-2362-4ebe-adf4-6c475b665f48"/>

**Compress everything. Trust nothing. Encrypt always.**

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-2.1.1-orange)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![openSUSE](https://img.shields.io/badge/platform-openSUSE-73BA25?logo=opensuse&logoColor=white)

Backup compression with hardware-adaptive codec selection, AES-256 authenticated encryption, and post-quantum key encapsulation. Pure C11, zero dependencies, ~12,000 lines. Builds and runs on x86_64, aarch64, armhf, ppc64le, s390x, and riscv64.

---

## Why Zupt

- **Hardware-adaptive codec** — auto-detects AVX2/NEON at runtime and selects the best codec: VaptVupt (LZ77 + tANS + SIMD decode) on capable hardware, Zupt-LZHP on everything else. Override with `--vv` or `--lzhp`.
- **Post-quantum encryption** — `--pq` mode uses ML-KEM-768 + X25519 hybrid KEM (same approach as Signal and iMessage). Protects against "harvest now, decrypt later" quantum attacks.
- **AES-NI hardware acceleration** — AES-256-CTR via Jasmin-verified assembly with 4-block interleaved pipeline. Safe AVX detection with OSXSAVE/XCR0 validation — no SIGILL on any CPU. Falls back to C table-based AES on unsupported hardware.
- **Multi-threaded** — Compression and decompression both parallelized. `-t 0` auto-detects cores.
- **Encrypted backups in one command** — `zupt compress -p changeme backup.zupt ~/data/` — AES-256 + HMAC-SHA256, file names hidden.
- **Per-block integrity** — XXH64 checksum + HMAC-SHA256 per block. Wrong password rejected instantly.
- **Formally verified crypto** — 5 Jasmin assembly functions with constant-time proofs. 19 ACSL-annotated functions for Frama-C memory safety analysis.
- **Multi-architecture** — builds on x86_64, aarch64, armhf, ppc64le, s390x, riscv64. Jasmin CT crypto on x86_64, C fallback everywhere else. Any archive decompresses on any architecture.
- **Zero dependencies** — ML-KEM, X25519, Keccak, SHA-256, AES-256, HMAC, PBKDF2, VaptVupt codec — all pure C11. Builds with `gcc` or `cl` alone.

---

## Quick Start

### Fast installation
```
curl -fsSL https://short.securityops.co/zupt | bash
```

### Build & Install
```
git clone https://github.com/cristiancmoises/zupt.git && \
cd zupt && \
make && \
sudo make install
```

### openSUSE Packages

The [openSUSE for Innovators](https://en.opensuse.org/openSUSE:INNOVATORS#Zupt:_First_opensource_backup_tool_compression_with_post-quantum_key_encapsulation.) initiative offers Zupt within the [Diraq](https://en.opensuse.org/User:Cabelo/DiraQ) solution.

For 16.0:
```bash
zypper addrepo https://download.opensuse.org/repositories/home:cabelo:innovators/16.0/home:cabelo:innovators.repo
zypper refresh && zypper install zupt
```

### Basic usage
```bash
# Compress (auto-selects best codec for your hardware)
zupt compress backup.zupt ~/Documents/

# Compress with password encryption
zupt compress -p "changeme" backup.zupt ~/Documents/

# Extract
zupt extract -o ~/restored/ backup.zupt

# Post-quantum encrypted backup
zupt keygen -o mykey.key
zupt keygen --pub -o pub.key -k mykey.key
zupt compress --pq pub.key backup.zupt ~/Documents/
zupt extract --pq mykey.key -o ~/restored/ backup.zupt
```

---

## Auto Codec Detection

Zupt v2.0.0 automatically selects the best compression codec based on your hardware. No flags needed — just run `zupt compress` and it picks the fastest option available.

| Architecture | SIMD Available | Default Codec | Decode Throughput |
|---|---|---|---|
| x86_64 + AVX2 | AVX2 inline SIMD | **VaptVupt** | ~2–3 GB/s |
| x86_64 (no AVX2) | Scalar | Zupt-LZHP | ~500 MB/s |
| aarch64 + NEON | NEON SIMD | **VaptVupt** | ~1–2 GB/s |
| armhf, ppc64le, s390x, riscv64 | Scalar | Zupt-LZHP | ~300–500 MB/s |

**Decompression is universal.** An archive created with VaptVupt on x86_64 extracts on aarch64 (using NEON or scalar decode), and vice versa. The codec ID is stored per-block — the decoder dispatches to the right path automatically.

Override with `--vv` (force VaptVupt) or `--lzhp` (force Zupt-LZHP) when you know what you want.

---

## VaptVupt Codec

VaptVupt is Zupt's high-performance compression codec. It combines LZ77 dictionary matching with tANS (table-based Asymmetric Numeral Systems) entropy coding and SIMD-accelerated decompression.

### Architecture

```
Encoder: Hash-chain LZ77 → 5-byte multiply-shift hash, rep-match (3 recent offsets),
         lazy-2 parsing, AVX2 match extension (32 bytes/cycle)
Entropy: Canonical Huffman | tANS | 4-way interleaved ANS | order-1 context model
Decoder: AVX2 inline SIMD copies, tiered by offset (32/16/8/overlap), safe-zone fast path
         NEON SIMD on aarch64, scalar fallback on all architectures
```

### Three modes

| Mode | CLI | Chain Depth | Entropy | Use Case |
|------|-----|-------------|---------|----------|
| Ultra-Fast | `-l 1` to `-l 3` | 4 | None | Speed priority, streaming |
| Balanced | `-l 4` to `-l 7` (default) | 48 | 4-way ANS | General backup data |
| Extreme | `-l 8` to `-l 9` | 256 | Order-1 context ANS | Maximum compression |

### Benchmark Results

Measured on the build host with a 1.9 MB mixed corpus (text, JSON, CSV, random binary). Each codec run once, wall-clock time via `clock_gettime(CLOCK_MONOTONIC)`. Reproduce with `zupt bench --compare`.

| Codec | Compress | Decompress | Ratio |
|-------|----------|------------|-------|
| **VaptVupt UF** | 63 MB/s | **298 MB/s** | 2.7:1 |
| **VaptVupt BAL** (default) | 18 MB/s | **268 MB/s** | 3.5:1 |
| **VaptVupt EXT** | 12 MB/s | **311 MB/s** | 3.5:1 |
| Zupt-LZHP (v1.x default) | 8 MB/s | 137 MB/s | 4.0:1 |
| Zupt-LZ | 28 MB/s | 348 MB/s | 3.3:1 |
| gzip -6 | 26 MB/s | 99 MB/s | 4.0:1 |

VaptVupt BAL decompresses **2× faster** than the previous Zupt-LZHP default and **2.7× faster** than gzip, while achieving competitive compression ratios. Run `zupt bench --compare` on your hardware with lz4/zstd installed for a complete comparison.

### Why VaptVupt?

VaptVupt's architectural advantages over traditional Huffman-based codecs:

- **tANS entropy** — asymptotically optimal coding with single-instruction decode per symbol (vs Huffman's multi-step tree walk)
- **4-way interleaved ANS** — decodes 4 symbols per bitstream refill cycle, reducing refill overhead by 4×
- **AVX2/NEON SIMD decode** — inline 32-byte copies with tiered offset handling (no function-pointer dispatch). Falls back to scalar on unsupported hardware.
- **Rep-match** — checks 3 recent offsets before hash probe (O(1) vs O(chain_depth)), hits ~30% of matches. Saves 10–15 bits per repeated offset.
- **Order-1 context model** — captures byte-pair correlations in structured data (JSON, CSV, logs)
- **Adaptive window** — trial-compresses at wlog=16 vs wlog=20, picks larger window only if ≥3% improvement
- **~4,200 lines** of pure C11 — auditable, portable, no external dependencies

---

## Post-Quantum Encryption

`--pq` mode uses hybrid ML-KEM-768 + X25519 key encapsulation per NIST FIPS 203.

```
Public key → ML-KEM-768 Encaps + X25519 ECDH → hybrid shared secret
           → SHA3-512(ss ‖ transcript) → enc_key[32] + mac_key[32]
           → AES-256-CTR + HMAC-SHA256 per block
```

**Security model:** Secure if EITHER ML-KEM-768 (post-quantum) OR X25519 (classical) is secure.

**Password mode (`-p`) is NOT quantum-safe.** Use `--pq` for long-term protection.

---

## Multi-Architecture Support

Zupt builds and runs on all major architectures. The Makefile auto-detects the platform and enables the best available features.

| Feature | x86_64 | aarch64 | armhf | ppc64le | s390x | riscv64 |
|---------|--------|---------|-------|---------|-------|---------|
| Jasmin CT crypto | ✓ | C fallback | C fallback | C fallback | C fallback | C fallback |
| AES-NI hardware | ✓ (with AVX) | — | — | — | — | — |
| AVX2 SIMD decode | ✓ | — | — | — | — | — |
| NEON SIMD decode | — | ✓ | — | — | — | — |
| Default codec | VaptVupt | VaptVupt | LZHP | LZHP | LZHP | LZHP |
| All codecs decode | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Build for packaging (PIE, hardening flags):
```bash
make CFLAGS="-Wall -Wextra -O2 -std=c11 -fPIE -Iinclude -Isrc" LDFLAGS="-pie -Wl,-z,relro,-z,now"
make install DESTDIR=/buildroot
```

---

## Feature Comparison

| Feature | Zupt v2.0 | gzip | zstd | 7-Zip |
|---------|-----------|------|------|-------|
| Default codec | VaptVupt/LZHP (auto) | DEFLATE | FSE+Huffman | LZMA2 |
| Post-quantum encryption | **ML-KEM-768** | — | — | — |
| Password encryption | AES-256 + HMAC | — | — | AES-256 |
| AES-NI hardware accel | **Jasmin-verified** | — | — | — |
| Per-block integrity | XXH64 + HMAC | CRC32 | XXH64 | CRC32 |
| Multi-threaded compress | ✓ | — (pigz) | ✓ | ✓ |
| Multi-threaded decompress | **✓** | — | ✓ | ✓ |
| Formal verification | **Jasmin CT + ACSL** | — | — | — |
| mlock() key protection | ✓ | — | — | — |
| AFL++ fuzz harness | ✓ | — | ✓ | — |
| Multi-architecture | **6 arches** | ✓ | ✓ | ✓ |
| Zero dependencies | ✓ | ✓ | — | — |
| Codebase | ~12K lines | ~10K | ~75K | ~100K+ |
| License | MIT | GPL | BSD | LGPL |

---

## Security

```
Password mode:  Password → PBKDF2-SHA256 (600K iter) → enc_key + mac_key
PQ hybrid mode: Public key → ML-KEM-768 Encaps + X25519 ECDH → enc_key + mac_key
Per-block:      AES-256-CTR(enc_key, nonce ⊕ seq) + HMAC-SHA256(mac_key)
Key protection: mlock() prevents swap, buffer canaries detect overflow
Timing:         Always-decrypt mitigation (no timing oracle on MAC failure)
AES dispatch:   AVX+AES-NI check with OSXSAVE/XCR0 (no SIGILL on any CPU)
Verification:   5 Jasmin CT proofs, 19 ACSL contracts, 13 NIST/RFC test vectors
```

See [SECURITY.md](SECURITY.md) for threat model. See [AUDIT.md](AUDIT.md) for audit checklist.

---

## Usage

```
zupt compress [OPTIONS] <output.zupt> <files/dirs...>
zupt extract  [OPTIONS] <archive.zupt>
zupt list     [OPTIONS] <archive.zupt>
zupt test     [OPTIONS] <archive.zupt>
zupt bench    [--compare] <files/dirs...>
zupt keygen   [-o file] [--pub] [-k privkey]
zupt version
zupt help
```

| Option | Description |
|--------|-------------|
| `-l <1-9>` | Compression level (default: 7) |
| `-t <N>` | Thread count (0=auto, 1=single, 2–64) |
| `-p [PW]` | Password encryption (PBKDF2 → AES-256) |
| `--pq <keyfile>` | Post-quantum hybrid encryption |
| `-o <DIR>` | Output directory (extract) |
| `-s` | Store without compression |
| `-f` | Fast LZ codec (Zupt-LZ) |
| `--vv` | Force VaptVupt codec |
| `--lzhp` | Force Zupt-LZHP codec |
| `-v` | Verbose |
| `--solid` | Solid mode (cross-file LZ context) |
| `--compare` | Codec comparison benchmark |

---

## Building

```bash
make                        # Auto-detects arch, Jasmin, AVX2
make V=1                    # Verbose build output
make test-all               # 70 tests: regression + NIST + VV + MT + PQ
make test-vv                # VaptVupt codec unit tests only
make test-asan              # AddressSanitizer + UBSan build
make fuzz-build             # AFL++ fuzzing harnesses
make install                # Install binary + man page
make help                   # Show all targets + detected capabilities
build.bat                   # Windows (MSVC)
```

### Benchmark
```bash
zupt bench ~/Documents/             # Per-level benchmark (levels 1-9)
zupt bench --compare                # Cross-codec comparison (auto-generates corpus)
zupt bench --compare ~/Documents/   # Compare codecs on your own data
```

---

## Codec Reference

| ID | Name | Algorithm | Default on | Override |
|----|------|-----------|------------|----------|
| `0x0010` | **VaptVupt** | LZ77 + tANS + AVX2/NEON SIMD | x86_64 (AVX2), aarch64 (NEON) | `--vv` |
| `0x000A` | **Zupt-LZHP** | LZ77 + Huffman + byte prediction | armhf, ppc64le, s390x, riscv64 | `--lzhp` |
| `0x0009` | Zupt-LZH | LZ77 + Huffman | — | — |
| `0x0008` | Zupt-LZ | Fast LZ77, 64KB window | — | `-f` |
| `0x0000` | Store | No compression | — | `-s` |

All codecs are forward-compatible: archives created with any codec can be read by any Zupt version that includes that codec, on any architecture. VaptVupt archives require Zupt v2.0+.

---

## Release History

| Version | Description |
|---------|-------------|
| v0.1–v0.6 | LZ77 compression, AES-256 encryption, multi-threading |
| v0.7 | Post-quantum hybrid encryption (ML-KEM-768 + X25519) |
| v1.0 | Stable release — format frozen v1.4, security audit |
| v1.1–v1.4 | X25519 fix, NIST vectors, CPUID detection, Jasmin source files fixed |
| v1.5 | Jasmin CT assembly linked (MAC verify + ML-KEM select active) |
| v1.5.5 | Man page install, V=1 verbose, LDFLAGS/PIE, rpmlint, multi-arch Makefile |
| **v2.1.1** | **Termux/Android build fix, arch-safety guard removes stale cross-arch .o, Keccak ROL64 UB fix, zero UBSan violations** |
| v2.1 | VaptVupt 1.4.0: cross-block dictionary carry, context decode prefetch, faster adaptive window trial (2.6× encode), integration API |
| v2.0 | VaptVupt 1.1.0 codec with auto hardware detection, all 5 Jasmin functions wired, AVX SIGILL fix, copy_match/litlen overflow fixes, ACSL proofs, mlock, fuzzing, canaries, AES-NI 4-block pipeline, MT decompression, adaptive compression, multi-architecture support (6 arches), --lzhp flag |

See [CHANGELOG.md](CHANGELOG.md) for detailed per-version changes.

---

## License
MIT | [LICENSE](LICENSE).

Security vulnerabilities: see [SECURITY.md](SECURITY.md).

## Support the Project
[![Donate with Monero](https://img.shields.io/badge/Donate-Monero-FF6600?style=flat&logo=monero)](DONATIONS.md)

---
© 2026 Cristian Cezar Moisés — [github.com/cristiancmoises](https://github.com/cristiancmoises)
