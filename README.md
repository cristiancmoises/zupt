<!-- Logo: rehost on git.securityops.co/cristiancmoises/zupt or zupt.securityops.co; old GitHub user-attachments URL no longer in use -->
<!-- <img width="493" height="173" alt="logo" src="https://zupt.securityops.co/assets/logo.png"/> -->

# Zupt

**Compress everything. Trust nothing. Encrypt always.**

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)
![Version](https://img.shields.io/badge/version-2.2.3-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

Backup compression with hardware-adaptive codec selection, AES-256 authenticated encryption, post-quantum key encapsulation, and full-disk backup. Pure C11, zero dependencies, ~13,000 lines. Builds and runs on x86_64, aarch64, armhf, ppc64le, s390x, and riscv64.

---

## Why Zupt

- **Hardware-adaptive codec** — auto-detects AVX2/NEON at runtime and selects the best codec: VaptVupt (LZ77 + tANS + SIMD decode) on capable hardware, Zupt-LZHP on everything else. Override with `--vv` or `--lzhp`.
- **Post-quantum encryption** — `--pq` mode uses ML-KEM-768 + X25519 hybrid KEM (same approach as Signal and iMessage). Protects against "harvest now, decrypt later" quantum attacks.
- **AES-NI hardware acceleration** — AES-256-CTR via Jasmin-verified assembly with 4-block interleaved pipeline. Safe AVX detection with OSXSAVE/XCR0 validation — no SIGILL on any CPU. Falls back to C table-based AES on unsupported hardware.
- **Multi-threaded** — Compression and decompression both parallelized. `-t 0` auto-detects cores.
- **Full-disk backup** — `zupt disk backup` clones entire disks or partitions in one command. Sparse block detection skips zero regions, real-time progress bar, all encryption modes supported. Restore with byte-for-byte verification via per-block XXH64 checksums.
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
git clone https://git.securityops.co/cristiancmoises/zupt.git && \
cd zupt && \
make && \
sudo make install
```

### Pre-built packages

| Format | File | Distros |
|---|---|---|
| Debian/Ubuntu | `zupt_2.2.3_amd64.deb` | Debian 11+, Ubuntu 22.04+, Mint 21+ |
| RPM | `zupt-2.2.3-1.x86_64.rpm` | Fedora 38+, RHEL 9+, openSUSE, AlmaLinux, Rocky, and other RPM-based distributions |
| AppImage | `zupt-2.2.3-x86_64.AppImage` | Any glibc 2.28+ (single-file, no install) |
| AppDir tarball | `zupt-2.2.3-x86_64.AppDir.tar.gz` | Any glibc 2.28+ (extract & run) |
| Generic tarball | `zupt-2.2.3-linux-x86_64.tar.gz` | Any Linux x86_64 (binary + man page) |
| Source | `zupt-2.2.3-source.tar.gz` | Build from source |

```bash
# Debian / Ubuntu / Mint
sudo dpkg -i zupt_2.2.3_amd64.deb
sudo apt-get install -f       # resolve any missing deps

# Fedora / RHEL / openSUSE / AlmaLinux / Rocky and other RPM-based distros
sudo rpm -i zupt-2.2.3-1.x86_64.rpm
# or
sudo dnf install ./zupt-2.2.3-1.x86_64.rpm

# AppImage (single executable, runs anywhere)
chmod +x zupt-2.2.3-x86_64.AppImage
./zupt-2.2.3-x86_64.AppImage --help
# Optionally place in PATH:
sudo install -m 755 zupt-2.2.3-x86_64.AppImage /usr/local/bin/zupt

# AppDir tarball (no install, no FUSE required)
tar xzf zupt-2.2.3-x86_64.AppDir.tar.gz
./zupt-2.2.3-x86_64.AppDir/AppRun --help

# Generic tarball (binary + man page, install manually)
tar xzf zupt-2.2.3-linux-x86_64.tar.gz
sudo install -m 755 zupt-2.2.3-linux-x86_64/zupt /usr/local/bin/zupt
sudo install -m 644 zupt-2.2.3-linux-x86_64/zupt.1.gz /usr/local/share/man/man1/
```

### Building from SRPM (Fedora / RHEL / RPM-based distributions)

```bash
tar xzf zupt-2.2.3.srpm.tar.gz
cd ~/rpmbuild  # or use rpmbuild --define "_topdir $(pwd)"
rpmbuild -bb SPECS/zupt.spec
sudo rpm -i RPMS/x86_64/zupt-2.2.3-1.*.rpm
```

### Basic usage

```bash
# Compress a directory (auto-selects best codec for your hardware)
zupt compress backup.zupt ~/Documents/

# Compress at a specific level (1=fast, 5=balanced, 9=extreme)
zupt compress -l 9 backup.zupt ~/Documents/

# Force the VaptVupt codec (default on AVX2/NEON hardware)
zupt compress --vv -l 5 backup.zupt ~/Documents/

# Compress with multi-threading (-t 0 = auto-detect cores)
zupt compress -t 0 -l 5 backup.zupt ~/Documents/

# Compress with password encryption (AES-256-CTR + HMAC-SHA256)
zupt compress -p "my-strong-password" backup.zupt ~/Documents/

# List archive contents
zupt list backup.zupt

# Show archive metadata (codec, blocks, encryption — no password needed)
zupt info backup.zupt

# Verify archive integrity (HMAC + per-block checksums)
zupt test backup.zupt
zupt test -p "my-strong-password" backup.zupt

# Extract everything
zupt extract -o ~/restored/ backup.zupt

# Extract from encrypted archive
zupt extract -p "my-strong-password" -o ~/restored/ backup.zupt

# Benchmark all 9 levels on a file
zupt bench big-file.tar
```

#### Post-quantum encryption

```bash
# Recommended: SDK v2 (HKDF combiner + key commitment + HPKE binding + Argon2id).
# New archives should use this.
zupt keygen --sdk -o mykey.priv     # writes mykey.priv and mykey.priv.pub
zupt compress --pq-sdk mykey.priv.pub backup.zupt ~/Documents/
zupt extract  --pq-sdk mykey.priv -o ~/restored/ backup.zupt

# Legacy --pq mode (XOR+SHA3-512 combiner) — kept for back-compat with
# archives created by Zupt 2.0–2.1. Do NOT use for new archives.
zupt keygen -o mykey.key
zupt keygen --pub -o pub.key -k mykey.key
zupt compress --pq pub.key backup.zupt ~/Documents/
zupt extract --pq mykey.key -o ~/restored/ backup.zupt
```

#### Full-disk backup

```bash
# Backup an entire disk or partition (sparse-detection skips zero regions)
sudo zupt disk backup -l 5 disk.zupt /dev/sda

# Backup with encryption
sudo zupt disk backup -p "passphrase" -l 5 disk.zupt /dev/sda

# Restore (writes raw bytes back to a block device or file)
sudo zupt disk restore disk.zupt /dev/sdb
sudo zupt disk restore -p "passphrase" disk.zupt /dev/sdb

# Backup a partition image file (no root needed)
zupt disk backup -l 5 part.zupt /path/to/partition.img
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

**This release embeds VaptVupt 2.48.2** — the version cut explicitly as the integration target for Zupt 2.2.3. See `CHANGELOG.md` for the full list of changes.

### Architecture

```
Encoder: Hash-chain LZ77 → 5-byte multiply-shift hash, rep-match (3 recent offsets),
         lazy-2 parsing, AVX2 match extension (32 bytes/cycle), cost-aware lazy parser
Entropy: Canonical Huffman | tANS | 4-way interleaved ANS | order-1 context model
         4-stream Huffman literal coding (lit_fmt=4) for structured data
Decoder: AVX2 inline SIMD copies, tiered by offset (32/16/8/overlap), safe-zone fast path
         NEON SIMD on aarch64, scalar fallback on all architectures
Format:  v1 frame (default) and v2 frame (T-tag, min_match=3) for binary data
```

### Three modes

| Mode | CLI | Chain Depth | Entropy | Use Case |
|------|-----|-------------|---------|----------|
| Ultra-Fast | `-l 1` to `-l 2` | 4 | None | Speed priority, streaming |
| Balanced | `-l 3` to `-l 7` (default) | 48 | 4-way ANS | General backup data |
| Extreme | `-l 8` to `-l 9` | 256 | Order-1 context ANS + cost-aware lazy parser | Maximum compression |

The Zupt wrapper enables VaptVupt's `format_v2` flag (4–7% better real-binary ratio) automatically for Balanced and Extreme modes. Ultra-Fast stays on the v1 frame because the `format_v2 + ULTRA_FAST` combination is not yet covered by VaptVupt's upstream test matrix.

### Benchmark Results (this release)

Measured on the build host with a 4 MB mixed corpus (text records.csv, random.bin). Each codec run once, wall-clock via `time(NULL)` boundaries. Reproduce with `zupt bench <file>`.

| Codec / Level | text 4MB → ratio | random 4MB → ratio | Notes |
|---|---|---|---|
| **VaptVupt L1** (UltraFast) | 4.31:1 | ~1.00:1 | Fastest |
| **VaptVupt L3** (Balanced + format_v2) | **15.83:1** | ~1.00:1 | Default sweet spot |
| **VaptVupt L5** (Balanced + format_v2) | 15.40:1 | ~1.00:1 | |
| **VaptVupt L9** (Extreme + format_v2) | 15.23:1 | ~1.00:1 | Max ratio |
| gzip -9 | 8.70:1 | ~1.00:1 | Baseline |

On the standard Silesia + fixture suite measured by the upstream VaptVupt project, v2.48.x **beats zstd-3 by 1.07% in aggregate ratio** (was +1.2% behind in v2.47.x), with decode throughput at **1.27× zstd-3** in aggregate and **3.7× zstd-19 / 1.5× lz4-9** on AEAD-shaped (random) data with `--fast`.

### Why VaptVupt?

VaptVupt's architectural advantages over traditional Huffman-based codecs:

- **tANS entropy** — asymptotically optimal coding with single-instruction decode per symbol (vs Huffman's multi-step tree walk)
- **4-way interleaved ANS** — decodes 4 symbols per bitstream refill cycle, reducing refill overhead by 4×
- **4-stream Huffman literal coding** (`lit_fmt=4`) — Sprint 105 addition that further improves ratio on structured data
- **AVX2/NEON SIMD decode** — inline 32-byte copies with tiered offset handling (no function-pointer dispatch). Falls back to scalar on unsupported hardware.
- **Rep-match** — checks 3 recent offsets before hash probe (O(1) vs O(chain_depth)), hits ~30% of matches. Saves 10–15 bits per repeated offset.
- **Order-1 context model** — captures byte-pair correlations in structured data (JSON, CSV, logs)
- **Cost-aware lazy parser** (Sprint 120) — the breakthrough that put EXTREME ahead of zstd-3 in aggregate ratio
- **Adaptive window** — trial-compresses at wlog=16 vs wlog=20, picks larger window only if ≥3% improvement
- **`format_v2` (T-tag, min_match=3)** — 4–7% better binary ratio; transparent to v2.33.0+ decoders
- **Memory hygiene** (Sprint 118) — encoder working buffers scrubbed via `vv_secure_zero` before `free()`
- **~6,500 lines** of pure C11 — auditable, portable, no external dependencies

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

## Full-Disk Backup

Clone entire disks, partitions, or raw images with compression and encryption in one command.

### Quick start
```bash
# Clone a partition (requires read access)
sudo zupt disk backup backup.zupt /dev/sda1

# Clone with post-quantum encryption (strongest)
zupt keygen -o mykey.key
zupt keygen --pub -o pub.key -k mykey.key
sudo zupt disk backup --pq pub.key backup.zupt /dev/nvme0n1p2

# Clone with password encryption
sudo zupt disk backup -p backup.zupt /dev/sda1

# Maximum compression (level 9, extreme mode)
sudo zupt disk backup -l 9 backup.zupt /dev/sda1

# Restore to a device or file
sudo zupt disk restore backup.zupt /dev/sda1
sudo zupt disk restore --pq mykey.key backup.zupt /dev/sda1
```

### How it works

```
Source device → Read 4MB blocks → Sparse detection → Compress → Encrypt → Write .zupt
                                      │                 │          │
                                      │                 │          └─ AES-256-CTR + HMAC-SHA256
                                      │                 └─ VaptVupt/LZHP (auto-selected)
                                      └─ Zero blocks stored as STORE (near-zero overhead)
```

Zupt reads the source device sequentially in 4MB chunks. Each block is checked for all-zero content (sparse detection uses 8-byte-wide comparison). Zero blocks are stored with codec `STORE` — effectively just the block header with no payload, saving both compression CPU time and archive space. Non-zero blocks are compressed with the selected codec and optionally encrypted. Per-block XXH64 checksums ensure byte-for-byte integrity on restore.

### Best practices

**Encryption hierarchy (strongest → fastest):**

| Mode | Command | Security Level | Speed Impact |
|------|---------|---------------|-------------|
| PQ Hybrid | `--pq pub.key` | Quantum-resistant + classical | ~5% overhead |
| Password | `-p` | AES-256, PBKDF2 600K iter | ~3% overhead |
| None | (default) | Integrity only (XXH64) | Fastest |

**Compression levels for disks:**

| Level | Mode | Best for | Typical ratio |
|-------|------|----------|--------------|
| `-l 1` to `-l 3` | Ultra-Fast | Live systems, NVMe (speed priority) | 1.5–2.5:1 |
| `-l 4` to `-l 7` | Balanced (default) | General partitions, ext4/NTFS | 2–5:1 |
| `-l 8` to `-l 9` | Extreme | Cold storage, archival backups | 3–10:1 |

**Operational guidance:**

- **Unmount before backup** for filesystem consistency. For live systems, use LVM snapshots or filesystem freeze: `fsfreeze -f /mnt/data && zupt disk backup ... && fsfreeze -u /mnt/data`.
- **Block devices require root** on Linux. Regular files (disk images, `.img`, `.raw`) do not.
- **Sparse-heavy disks** (freshly formatted, VMs with thin provisioning) compress extremely well — the sparse detector skips zero blocks at memory-copy speed with no compression overhead.
- **Verify after backup** with `zupt test archive.zupt` — checks every block's XXH64 checksum without extracting.
- **PQ encryption for long-term** — disk backups stored for years should use `--pq` to resist future quantum attacks. Generate one keypair, store the private key offline, distribute the public key.
- **Restore is non-destructive on files** — writing to a regular file creates/overwrites it. Writing to a block device overwrites the raw device. Double-check the target path before restoring to a device.

### Comparison with other tools

| Feature | Zupt disk | dd + gzip | Clonezilla | partclone |
|---------|-----------|-----------|------------|-----------|
| Compression | VaptVupt/LZHP (adaptive) | gzip (fixed) | Multiple | Multiple |
| Encryption | AES-256 + PQ hybrid | None (pipe to gpg) | None | None |
| Sparse detection | Automatic | None | Filesystem-aware | Filesystem-aware |
| Per-block integrity | XXH64 per block | None | None | CRC32 |
| Single binary | ✓ (zero deps) | 2+ tools | ISO boot | Multiple |
| Post-quantum | ML-KEM-768 | — | — | — |
| Cross-platform | 6 architectures | ✓ | x86 only | Linux only |

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

| Feature | Zupt v2.1 | gzip | zstd | 7-Zip |
|---------|-----------|------|------|-------|
| Default codec | VaptVupt/LZHP (auto) | DEFLATE | FSE+Huffman | LZMA2 |
| Full-disk backup | **`zupt disk`** | — | — | — |
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
| License | **AGPL+GPL** | GPL/zlib | BSD-3 | LGPL+unRAR |

---

## Security

```
Password mode:  Password → PBKDF2-SHA256 (600K iter) → enc_key + mac_key
PQ hybrid mode: Public key → ML-KEM-768 Encaps + X25519 ECDH → enc_key + mac_key
SDK v2 mode:    HKDF-SHA3 combiner with domain separation + key commitment + HPKE binding
Per-block:      AES-256-CTR(enc_key, nonce ⊕ seq) + HMAC-SHA256(mac_key)
Key protection: mlock() prevents swap, buffer canaries detect overflow
Timing:         Always-decrypt mitigation (no timing oracle on MAC failure)
AES dispatch:   AVX+AES-NI check with OSXSAVE/XCR0 (no SIGILL on any CPU)
Path safety:    Zip Slip / symlink defenses (zupt_path_is_safe + O_NOFOLLOW)
Verification:   5 Jasmin CT proofs, 19 ACSL contracts, 13 NIST/RFC test vectors
```

**Audit history:** Three internal audit sprints conducted on the 2.2.x line.
**14 bugs** found and fixed across the sprints — including one **HIGH-severity
Zip Slip path traversal** caught in the formal audit pass. Cumulative test
surface: **265 tests** (47 zupt + 169 SDK + 49 inherited) plus **751,000
mutation-fuzz iterations** under ASAN/UBSAN, all passing. No external audit
yet — see SECURITY.md for honest scope.

See [SECURITY.md](SECURITY.md) for threat model. See [AUDIT.md](AUDIT.md) for
audit history. See [FORMAL_AUDIT_PROMPT.md](FORMAL_AUDIT_PROMPT.md) for the
methodology used in audit sprints.

---

## Usage

```
zupt compress [OPTIONS] <output.zupt> <files/dirs...>
zupt extract  [OPTIONS] <archive.zupt>
zupt list     [OPTIONS] <archive.zupt>
zupt test     [OPTIONS] <archive.zupt>
zupt disk     backup [OPTIONS] <output.zupt> <device_or_file>
zupt disk     restore [OPTIONS] <archive.zupt> <target>
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
make test-all               # 77 tests: regression + NIST + VV + MT + PQ + disk
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
| v1.5.5 | Build system improvements: man page install rules, verbose mode, multi-arch detection |
| v2.0 | VaptVupt 1.1.0 codec, auto hardware detection, all 5 Jasmin wired, AVX SIGILL fix, copy_match/litlen fixes, ACSL, mlock, fuzzing, canaries, AES-NI pipeline, MT decompress, multi-arch (6 arches), --lzhp flag |
| v2.1.0 | VaptVupt 1.4.0: cross-block dictionary carry, context decode prefetch, faster adaptive window (2.6× encode), integration API |
| v2.1.1 | Termux/Android build fix, arch-safety guard, Keccak ROL64 UB fix, zero UBSan violations |
| v2.1.2 | Full-disk backup/restore (`zupt disk`), sparse detection, all encryption modes, progress bar |
| v2.1.3 | LZHP prediction encoding fix (data corruption on structured data), shared write_enc_header, SOLID flag removed from disk, 78 tests |
| v2.1.4 | CodeQL: 4 security fixes — TOCTOU races eliminated (fstat on fd), X25519 scalar wipe via volatile |
| v2.1.5 | Block-level deduplication (`--dedup`), XXH64 fingerprint index, DEDUP_REF block type, 81 tests |
| v2.2.0–v2.2.2 | libzuptsdk 2.0 integration (HKDF-SHA3 combiner + key commitment + HPKE binding + Argon2id), `--pq-sdk` mode (XChaCha20-Poly1305 / AES-256-SIV), license-hygiene cleanup, full SPDX coverage |
| **v2.2.3** | **VaptVupt 2.48.2 codec integration: cost-aware lazy parser (beats zstd-3 by 1.07% aggregate), 4-stream Huffman, `format_v2` flag (4–7% better binary), `compat_v246_5_decoder` flag, encoder memory hygiene (`vv_secure_zero` on free), Sprint 117 hardened-build compatibility. Wrapper defaults applied per upstream `ZUPT_INTEGRATION.md`: `checksum=0` (Zupt's outer MAC authenticates), `format_v2=1` for BALANCED/EXTREME (defensive guard against the upstream-untested `format_v2 + ULTRA_FAST` combo). Makefile arch-detection bug fixed (`x86-64` ≠ `x86_64` mismatch). 22/22 regression tests, 14/14 threaded, 10/10 PQ, 11/11 VaptVupt, 13/13 NIST vectors, ASAN/UBSAN clean across plain/password/PQ-SDK at all levels.** |

See [CHANGELOG.md](CHANGELOG.md) for detailed per-version changes.

---

## License

Zupt is **dual-licensed**:

- **AGPL-3.0-or-later** — most of the codebase (CLI, libzuptsdk, GUI, Jasmin source). See [`LICENSE`](LICENSE).
- **GPL-3.0-or-later** — the VaptVupt LZ codec only (`src/vv_*.c`, `src/vaptvupt_api.c` and headers). VaptVupt is GPL so it can be considered for upstreaming into the Linux/BSD kernels.
- **Commercial license** available for relief from AGPL/GPL terms. Contact `sac@securityops.co`.

Every source file carries an explicit SPDX header. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for full attribution. Zupt contains **no third-party source code** — every line is original work.

Security vulnerabilities: see [SECURITY.md](SECURITY.md).

## Related projects

All by Cristian Cezar Moisés, hosted on git.securityops.co:

- [zupt](https://git.securityops.co/cristiancmoises/zupt) — this repo (CLI + GUI)
- [zupt-android](https://git.securityops.co/cristiancmoises/zupt-android) — Android port
- [zupt-web](https://git.securityops.co/cristiancmoises/zupt-web) — Web frontend
- [libzuptsdk](https://git.securityops.co/cristiancmoises/libzuptsdk) — Standalone C SDK
- [vaptvupt](https://git.securityops.co/cristiancmoises/vaptvupt) — Standalone LZ + tANS codec

## Support the Project
If you find Zupt useful, please consider sharing it or contributing — see the README footer for contact links.

---
© 2026 Cristian Cezar Moisés — [git.securityops.co/cristiancmoises](https://git.securityops.co/cristiancmoises)
