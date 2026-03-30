<img width="493" height="173" alt="logo" src="https://github.com/user-attachments/assets/164f5217-2362-4ebe-adf4-6c475b665f48"/>

**Compress everything. Trust nothing. Encrypt always.**

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-2.0.0-orange)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![openSUSE](https://img.shields.io/badge/platform-openSUSE-73BA25?logo=opensuse&logoColor=white)

Backup compression with the VaptVupt codec, AES-256 authenticated encryption, and post-quantum key encapsulation. Pure C11, zero dependencies, ~12,000 lines.

---
Some fixes have been made in version 2.0-RC it is already suitable for *personal use* and *testing*, but *not yet for critical environments* or *large-scale data*.
See [SECURITY.md](SECURITY.md) for threat model. See [AUDIT.md](AUDIT.md) for audit checklist.

`❗Please wait for the full version 2.0 release, which will fix all remaining bugs and improve performance.`

---

## Why Zupt

- **VaptVupt codec** — LZ77 + tANS entropy coding with AVX2 SIMD decode. Decompresses 2–3× faster than the previous Zupt-LZHP codec and matches gzip-level ratios with better decode throughput.
- **Post-quantum encryption** — `--pq` mode uses ML-KEM-768 + X25519 hybrid KEM (same approach as Signal and iMessage). Protects against "harvest now, decrypt later" quantum attacks.
- **AES-NI hardware acceleration** — AES-256-CTR via Jasmin-verified assembly with 4-block interleaved pipeline. No table-based AES on supported CPUs — eliminates cache-timing side channels.
- **Multi-threaded** — Compression and decompression both parallelized. `-t 0` auto-detects cores.
- **Encrypted backups in one command** — `zupt compress -p "changeme" backup.zupt ~/data/` — AES-256 + HMAC-SHA256, file names hidden.
- **Per-block integrity** — XXH64 checksum + HMAC-SHA256 per block. Wrong password rejected instantly.
- **Formally verified crypto** — 5 Jasmin assembly functions with constant-time proofs. 19 ACSL-annotated functions for Frama-C memory safety analysis.
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
# Compress (VaptVupt codec, default)
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

## VaptVupt Codec

VaptVupt is Zupt's default compression codec since v2.0.0. It combines LZ77 dictionary matching with tANS (table-based Asymmetric Numeral Systems) entropy coding and AVX2 SIMD-accelerated decompression.

### Architecture

```
Encoder: Hash-chain LZ77 → 5-byte multiply-shift hash, rep-match (3 recent offsets),
         lazy-2 parsing, AVX2 match extension (32 bytes/cycle)
Entropy: Canonical Huffman | tANS | 4-way interleaved ANS | order-1 context model
Decoder: AVX2 inline SIMD copies, tiered by offset (32/16/8/overlap), safe-zone fast path
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
- **AVX2 SIMD decode** — inline 32-byte copies with tiered offset handling (no function-pointer dispatch)
- **Rep-match** — checks 3 recent offsets before hash probe (O(1) vs O(chain_depth)), hits ~30% of matches
- **Order-1 context model** — captures byte-pair correlations in structured data (JSON, CSV, logs)
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

## Feature Comparison

| Feature | Zupt v2.0 | gzip | zstd | 7-Zip |
|---------|-----------|------|------|-------|
| Default codec | VaptVupt (ANS) | DEFLATE | FSE+Huffman | LZMA2 |
| Post-quantum encryption | **ML-KEM-768** | — | — | — |
| Password encryption | AES-256 + HMAC | — | — | AES-256 |
| AES-NI hardware accel | **Jasmin-verified** | — | — | — |
| Per-block integrity | XXH64 + HMAC | CRC32 | XXH64 | CRC32 |
| Multi-threaded compress | ✓ | — (pigz) | ✓ | ✓ |
| Multi-threaded decompress | **✓** | — | ✓ | ✓ |
| Formal verification | **Jasmin CT + ACSL** | — | — | — |
| mlock() key protection | ✓ | — | — | — |
| AFL++ fuzz harness | ✓ | — | ✓ | — |
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
| `-l <1-9>` | Compression level (default: 7, VaptVupt balanced) |
| `-t <N>` | Thread count (0=auto, 1=single, 2–64) |
| `-p [PW]` | Password encryption (PBKDF2 → AES-256) |
| `--pq <keyfile>` | Post-quantum hybrid encryption |
| `-o <DIR>` | Output directory (extract) |
| `-s` | Store without compression |
| `-f` | Fast LZ codec (Zupt-LZ) |
| `--vv` | VaptVupt codec (default since v2.0) |
| `-v` | Verbose |
| `--solid` | Solid mode (cross-file LZ context) |
| `--compare` | Codec comparison benchmark |

---

## Building

```bash
make                        # Linux/macOS (auto-detects Jasmin .s files + AVX2)
make test-all               # 22 regression + 13 NIST vectors + 11 VV unit tests
make test-vv                # VaptVupt codec unit tests only
make test-asan              # AddressSanitizer + UBSan build
make fuzz-build             # AFL++ fuzzing harnesses
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

| ID | Name | Algorithm | When to use |
|----|------|-----------|-------------|
| `0x0010` | **VaptVupt** (default) | LZ77 + tANS + AVX2 SIMD | General use — best speed/ratio tradeoff |
| `0x000A` | Zupt-LZHP | LZ77 + Huffman + byte prediction | Legacy (v1.x default), slightly better ratio on some data |
| `0x0009` | Zupt-LZH | LZ77 + Huffman | Legacy, no prediction preprocessor |
| `0x0008` | Zupt-LZ | Fast LZ77, 64KB window | Speed priority (`-f` flag) |
| `0x0000` | Store | No compression | Incompressible data (`-s` flag) |

All codecs are forward-compatible: archives created with any codec can be read by any Zupt version that includes that codec. VaptVupt archives require Zupt v2.0+.

---

## Release History

| Version | Description |
|---------|-------------|
| v0.1–v0.6 | LZ77 compression, AES-256 encryption, multi-threading |
| v0.7 | Post-quantum hybrid encryption (ML-KEM-768 + X25519) |
| v1.0 | Stable release — format frozen v1.4, security audit |
| v1.1–v1.5 | X25519 fix, NIST vectors, CPUID detection, Jasmin CT proofs (2 of 4 wired) |
| **v2.0** | **VaptVupt codec (default), all 4 Jasmin functions wired, ACSL proofs, mlock, fuzzing, canaries, AES-NI 4-block pipeline, MT decompression, adaptive compression, benchmark harness** |

---

## License
MIT — see [LICENSE](LICENSE).

Security vulnerabilities: see [SECURITY.md](SECURITY.md).

## Support the Project
[![Donate with Monero](https://img.shields.io/badge/Donate-Monero-FF6600?style=flat&logo=monero)](DONATIONS.md)

---
© 2026 Cristian Cezar Moisés — [github.com/cristiancmoises](https://github.com/cristiancmoises)
