<!-- Logo: rehost on git.securityops.co/cristiancmoises/vaptvupt or zupt.securityops.co; old GitHub user-attachments URL no longer in use -->
<!-- <img width="493" height="173" alt="logo" src="https://zupt.securityops.co/assets/logo.png"/> -->

# VaptVupt

**Compress everything. Trust nothing. Encrypt always.**

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)
![Version](https://img.shields.io/badge/version-4.0.0-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

> **Renamed from "Zupt" in v3.0.0** because of a prior INPI Brasil
> trademark registration on the name "Zupt" for unrelated software.
> The `.zupt` archive extension and `ZUPT` header magic bytes are
> unchanged — v2.x and v3.0.0 archives are bidirectionally compatible.
> The `zupt` command is preserved as a symlink to `vaptvupt` for one
> major version cycle.

## What's new in 4.0.0

- **Codec security release** — vendored codec upgraded to VaptVupt 2.60.4, fixing a high-severity OOB heap write in the AVX2 decode fast path (reachable on valid streams with exact-size output buffers). 80 new exact-size decode regression cases under ASan.
- **`--pq-box` sealed-box mode** — third post-quantum recipient mode via vendored libpqvaptvupt 0.6.0: ML-KEM-768 + X25519 through an HKDF-SHA256 domain-separated combiner. `vaptvupt keygen --box` writes magic-tagged keypairs that reject key-type confusion.
- **F-16 disclosure and fix** — archives created by ≤ 3.8.0 at `-l 8`/`-l 9` containing x86/ELF/PE executables may be unreadable by *any* version (write-time defect in the old in-tree BCJ encoder). Re-create them with 4.0.0; details below and in [CHANGELOG.md](CHANGELOG.md).
- **SHA-NI measured** — 5.8× over scalar SHA-256 (204 → 1184 MB/s); encrypted per-block throughput now 293 MB/s.

Binaries for the CLI (4.0.0) and GUI (1.3.0) are on the
[release page](https://git.securityops.co/cristiancmoises/vaptvupt/releases/tag/v4.0.0).

Backup compression with hardware-adaptive codec selection, AES-256
authenticated encryption, post-quantum key encapsulation, and
full-disk backup. Pure C11, zero dependencies, ~13,000 lines. Builds
and runs on x86_64, aarch64, armhf, ppc64le, s390x, and riscv64.

---

## Why VaptVupt

- **Hardware-adaptive codec** — auto-detects AVX2/NEON at runtime and selects the best codec: VaptVupt (LZ77 + tANS + SIMD decode) on capable hardware, VaptVupt-LZHP on everything else. Override with `--vv` or `--lzhp`.
- **Post-quantum encryption** — `--pq` mode uses ML-KEM-768 + X25519 hybrid KEM (same approach as Signal and iMessage). Protects against "harvest now, decrypt later" quantum attacks.
- **AES-NI hardware acceleration** — AES-256-CTR via Jasmin-verified assembly with 4-block interleaved pipeline. Safe AVX detection with OSXSAVE/XCR0 validation — no SIGILL on any CPU. Falls back to C table-based AES on unsupported hardware.
- **SHA-NI hardware acceleration** — HMAC-SHA256 (the Encrypt-then-MAC second pass) and PBKDF2 use an Intel SHA-NI compression path (`SHA256RNDS2`/`MSG1`/`MSG2`) when the CPU supports it (Intel Goldmont+/Ice Lake+, AMD Zen+), selected at runtime via CPUID. **measured 5.8×** over the scalar path (204 → 1184 MB/s, 256 MiB, Xeon 2.10 GHz) *and* constant-time by construction. Bit-identical output; scalar C fallback elsewhere (incl. aarch64). `vaptvupt version` prints the live acceleration set for your CPU.
- **Incremental HMAC** — the per-block MAC streams its segments through an incremental HMAC-SHA256 (key prefix folded once per keyring) instead of copying each block's ciphertext into a temporary buffer. Removes a per-block heap allocation and full-payload copy on both encrypt and decrypt, with a byte-for-byte identical MAC (RFC 2104).
- **Multi-threaded** — Compression and decompression both parallelized. `-t 0` auto-detects cores.
- **Full-disk backup** — `vaptvupt disk backup` clones entire disks or partitions in one command. Sparse block detection skips zero regions, real-time progress bar, all encryption modes supported. Restore with byte-for-byte verification via per-block XXH64 checksums.
- **Encrypted backups in one command** — `vaptvupt compress -p changeme backup.zupt ~/data/` — AES-256 + HMAC-SHA256, file names hidden.
- **Per-block integrity** — XXH64 checksum + HMAC-SHA256 per block. Wrong password rejected instantly.
- **Self-describing KDF** — password archives record their key-derivation profile in the (authenticated) header, so an archive always carries the parameters needed to open it years later. Unknown profiles are refused fail-closed rather than mis-derived. Argon2id is the default; PBKDF2 (600K iter) via `--kdf pbkdf2`.
- **Measured constant-time comparisons** — every security-critical comparison (HMAC tag, archive-integrity trailer, and the ML-KEM-768 decapsulation implicit-rejection check) routes through a single audited primitive (`zupt_ct_memeq`, branch-free, volatile accumulator, length-independent) verified by a dudect-style Welch t-test in CI, not just annotated. Its data-dependent timing signal measures ~1% of a leaky-`memcmp` control in the same environment; a reintroduced early-return or inline loop fails the test (timing + source-routing guard).
- **Sealed-box PQ recipients (`--pq-box`, v4.0.0)** — third post-quantum mode via vendored libpqvaptvupt: ML-KEM-768 + X25519 combined through HKDF-SHA256 with domain separation ("pqvv-seal-v1"), AES-256-CTR + HMAC-SHA256 EtM in the box, magic-tagged keypair files that reject key-type confusion. Legacy `--pq` and `--pq-sdk` remain readable.
- **Formally verified crypto** — 5 Jasmin assembly functions with constant-time proofs. 19 ACSL-annotated functions for Frama-C memory safety analysis.
- **Multi-architecture** — builds on x86_64, aarch64, armhf, ppc64le, s390x, riscv64. Jasmin CT crypto on x86_64, C fallback everywhere else. Any archive decompresses on any architecture.
- **Zero dependencies** — ML-KEM, X25519, Keccak, SHA-256, AES-256, HMAC, PBKDF2, VaptVupt codec — all pure C11. Builds with `gcc` or `cl` alone.

---

## Quick Start

### Fast installation
```
curl -fsSL https://short.securityops.co/vaptvupt | bash
```

### Build & Install
```
git clone https://git.securityops.co/cristiancmoises/vaptvupt.git && \
cd vaptvupt && \
make && \
sudo make install
```

### Pre-built packages

All assets are published on the [v4.0.0 release page](https://git.securityops.co/cristiancmoises/vaptvupt/releases/tag/v4.0.0)
and verifiable against the published `SHA256SUMS.txt`.

**Command-line tool (`vaptvupt` 4.0.0):**

| Format | File | Distros |
|---|---|---|
| Debian/Ubuntu | `vaptvupt_4.0.0_amd64.deb` | Debian 11+, Ubuntu 22.04+, Mint 21+ |
| RPM | `vaptvupt-4.0.0-1.x86_64.rpm` | Fedora 38+, RHEL 9+, openSUSE, AlmaLinux, Rocky, and other RPM-based distributions |
| AppDir tarball | `vaptvupt-4.0.0-x86_64.AppDir.tar.gz` | Any glibc 2.28+ (extract & run, no FUSE) |
| Source tarball | `vaptvupt-4.0.0.tar.gz` | Build from source on any platform |
| openSUSE OBS | `vaptvupt-4.0.0-opensuse-obs.tar.gz` | Open Build Service source bundle |

**Graphical front-end (`vaptvupt-gui` 1.3.0):**

| Format | File | Distros |
|---|---|---|
| Debian/Ubuntu | `vaptvupt-gui_1.3.0_all.deb` | Debian 11+, Ubuntu 22.04+, Mint 21+ |
| RPM | `vaptvupt-gui-1.3.0-1.noarch.rpm` | RPM-based distributions |
| AppImage | `VaptVupt-GUI-1.3.0-x86_64.AppImage` | Any glibc 2.28+ (single-file, no install) |
| AppDir tarball | `VaptVupt-GUI-1.3.0-x86_64.AppDir.tar.gz` | Any glibc 2.28+ (extract & run) |

```bash
# Verify downloads first
sha256sum -c SHA256SUMS.txt

# Debian / Ubuntu / Mint
sudo dpkg -i vaptvupt_4.0.0_amd64.deb
sudo apt-get install -f       # resolve any missing deps

# Fedora / RHEL / openSUSE / AlmaLinux / Rocky and other RPM-based distros
sudo rpm -i vaptvupt-4.0.0-1.x86_64.rpm
# or
sudo dnf install ./vaptvupt-4.0.0-1.x86_64.rpm

# AppDir tarball (no install, no FUSE required)
tar xzf vaptvupt-4.0.0-x86_64.AppDir.tar.gz
./vaptvupt-4.0.0-x86_64.AppDir/AppRun --help

# GUI AppImage (single executable, runs anywhere)
chmod +x VaptVupt-GUI-1.3.0-x86_64.AppImage
./VaptVupt-GUI-1.3.0-x86_64.AppImage
```

### Building from SRPM (Fedora / RHEL / RPM-based distributions)

```bash
tar xzf vaptvupt-4.0.0.srpm.tar.gz
cd ~/rpmbuild  # or use rpmbuild --define "_topdir $(pwd)"
rpmbuild -bb SPECS/vaptvupt.spec
sudo rpm -i RPMS/x86_64/vaptvupt-4.0.0-1.*.rpm
```

### Basic usage

```bash
# Compress a directory (auto-selects best codec for your hardware)
vaptvupt compress backup.zupt ~/Documents/

# Compress at a specific level (1=fast, 5=balanced, 9=extreme)
vaptvupt compress -l 9 backup.zupt ~/Documents/

# Force the VaptVupt codec (default on AVX2/NEON hardware)
vaptvupt compress --vv -l 5 backup.zupt ~/Documents/

# Compress with multi-threading (-t 0 = auto-detect cores)
vaptvupt compress -t 0 -l 5 backup.zupt ~/Documents/

# Compress with password encryption (AES-256-CTR + HMAC-SHA256)
vaptvupt compress -p "my-strong-password" backup.zupt ~/Documents/

# List archive contents
vaptvupt list backup.zupt

# Show archive metadata (codec, blocks, encryption — no password needed)
vaptvupt info backup.zupt

# Verify archive integrity (HMAC + per-block checksums)
vaptvupt test backup.zupt
vaptvupt test -p "my-strong-password" backup.zupt

# Extract everything
vaptvupt extract -o ~/restored/ backup.zupt

# Extract from encrypted archive
vaptvupt extract -p "my-strong-password" -o ~/restored/ backup.zupt

# Benchmark all 9 levels on a file
vaptvupt bench big-file.tar
```

#### Post-quantum encryption

```bash
# Recommended: SDK v2 (HKDF combiner + key commitment + HPKE binding + Argon2id).
# New archives should use this.
vaptvupt keygen --sdk -o mykey.priv     # writes mykey.priv and mykey.priv.pub
vaptvupt compress --pq-sdk mykey.priv.pub backup.zupt ~/Documents/
vaptvupt extract  --pq-sdk mykey.priv -o ~/restored/ backup.zupt

# pq-box sealed-box workflow (v4.0.0; HKDF-SHA256 domain-separated combiner)
vaptvupt keygen --box -o box.key                       # writes box.key + box.key.pub
vaptvupt compress --pq-box box.key.pub backup.zupt ~/Documents/
vaptvupt extract  --pq-box box.key -o ~/restored/ backup.zupt

# Legacy --pq mode (XOR+SHA3-512 combiner) — kept for back-compat with
# archives created by Zupt 2.0–2.1. Do NOT use for new archives.
vaptvupt keygen -o mykey.key
vaptvupt keygen --pub -o pub.key -k mykey.key
vaptvupt compress --pq pub.key backup.zupt ~/Documents/
vaptvupt extract --pq mykey.key -o ~/restored/ backup.zupt
```

#### Full-disk backup

```bash
# Backup an entire disk or partition (sparse-detection skips zero regions)
sudo vaptvupt disk backup -l 5 disk.zupt /dev/sda

# Backup with encryption
sudo vaptvupt disk backup -p "passphrase" -l 5 disk.zupt /dev/sda

# Restore (writes raw bytes back to a block device or file)
sudo vaptvupt disk restore disk.zupt /dev/sdb
sudo vaptvupt disk restore -p "passphrase" disk.zupt /dev/sdb

# Backup a partition image file (no root needed)
vaptvupt disk backup -l 5 part.zupt /path/to/partition.img
```

---

## Auto Codec Detection

VaptVupt automatically selects the best compression codec based on your hardware (since v2.0.0). No flags needed — just run `vaptvupt compress` and it picks the fastest option available.

| Architecture | SIMD Available | Default Codec | Decode Throughput |
|---|---|---|---|
| x86_64 + AVX2 | AVX2 inline SIMD | **VaptVupt** | ~2–3 GB/s |
| x86_64 (no AVX2) | Scalar | VaptVupt-LZHP | ~500 MB/s |
| aarch64 + NEON | NEON SIMD | **VaptVupt** | ~1–2 GB/s |
| armhf, ppc64le, s390x, riscv64 | Scalar | VaptVupt-LZHP | ~300–500 MB/s |

**Decompression is universal.** An archive created with VaptVupt on x86_64 extracts on aarch64 (using NEON or scalar decode), and vice versa. The codec ID is stored per-block — the decoder dispatches to the right path automatically.

Override with `--vv` (force VaptVupt) or `--lzhp` (force VaptVupt-LZHP) when you know what you want.

---

## VaptVupt Codec

VaptVupt is the project's high-performance compression codec. It combines LZ77 dictionary matching with tANS (table-based Asymmetric Numeral Systems) entropy coding and SIMD-accelerated decompression.

**This release embeds VaptVupt 2.60.4** (security release: fixes an OOB
heap write in the AVX2 decode fast path; adds canonical CBMC-verified
BCJ filters with auto-detection). The codec API is byte-identical
to the 2.48.x line; the 2.48.5 → 2.60.4 upgrades add the optimal parser
(measured: text −1.95%, binary −1.31%, source −4.72% smaller on our
fixtures), large-window extreme mode, faster decode (now roughly on par
with zstd-19, up from 1.5–2× slower), and six upstream corrupt-input
decoder memory-safety fixes. See `CHANGELOG.md` for the full list.

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

The VaptVupt wrapper enables VaptVupt's `format_v2` flag (4–7% better real-binary ratio) automatically for Balanced and Extreme modes. Ultra-Fast stays on the v1 frame because the `format_v2 + ULTRA_FAST` combination is not yet covered by VaptVupt's upstream test matrix.

### Benchmark Results (codec 2.60.4)

> Full, reproducible measured benchmarks — compression ratio/speed
> across levels, crypto overhead (KDF vs per-block), and a head-to-head
> ratio comparison against zstd — are in **[`BENCHMARKS.md`](BENCHMARKS.md)**,
> with the test machine and method stated for every table.

> **F-16 (data loss, fixed in 4.0.0):** archives created by **≤ 3.8.0** at
> `-l 8`/`-l 9` whose inputs included x86/ELF/PE executables may be
> **undecodable by any version** (defect at write time in the old
> divergent BCJ encoder). Re-create such archives with 4.0.0 and verify
> extraction before deleting source data. Details in CHANGELOG/AUDIT.

**Measured against gzip-9, zstd-3, zstd-19** on a 4-fixture suite
(text 10 MB, binary-struct 7.5 MB, source code 10 MB, random 5 MB).
Decode timed across 3 runs, minimum reported; wall-clock including the
`.zupt` envelope (HMAC etc.). Host: Intel Xeon @ 2.1 GHz, single vCPU,
codec built at the distribution's default optimisation level (AVX2).
**Reproduce with `vaptvupt bench <file>`** to compare VaptVupt levels,
or the comparative harness in the source tree.

| Fixture       | Tool      | Ratio    | Dec MB/s |
|---------------|-----------|---------:|---------:|
| text 10 MB    | vv-9      | 25.6%    | 278      |
| text 10 MB    | gzip-9    | 22.6%    | 156      |
| text 10 MB    | zstd-3    | 24.2%    | 556      |
| text 10 MB    | zstd-19   | **17.6%**| 435      |
| binary 7.5 MB | vv-9      | 46.1%    | 300      |
| binary 7.5 MB | gzip-9    | 46.8%    | 123      |
| binary 7.5 MB | zstd-3    | 44.8%    | 577      |
| binary 7.5 MB | zstd-19   | **41.1%**| 417      |
| source 10 MB  | vv-9      | 4.5%     | 714      |
| source 10 MB  | gzip-9    | 4.0%     | 238      |
| source 10 MB  | zstd-3    | 5.6%     | 1000     |
| source 10 MB  | zstd-19   | **2.7%** | 769      |
| random 5 MB   | vv-9      | 100.0%   | 625      |
| random 5 MB   | zstd-3    | 100.0%   | 681      |

Honest reading (these are measured numbers, not aspirations):

- **On ratio, zstd-19 wins every fixture.** VaptVupt L9 lands between
  zstd-3 and zstd-19 on text and binary, beats zstd-3 on source (4.5%
  vs 5.6%), and loses to zstd-19 everywhere. If smallest-file is the
  only goal, use `xz -9` or `zstd -19`.
- **Decode is now competitive**, not a weakness: 278–714 MB/s, in the
  same band as zstd-19 (and within ~1.3× of zstd-3). The 2.60.4 codec's
  decode-speed work (Sprint 53/58) closed most of the gap that existed
  at 2.48.5. The earlier "1.27× zstd-3 decode" headline (inherited from
  upstream docs) is **not claimed here** — it did not reproduce in our
  own single-vCPU measurement.
- **Encode throughput remains the weakness.** The optimal parser and
  depth-24 hash-chain walk that win ratio cost encode speed; balanced
  mode is ~6× slower than fast and ~14× slower than zstd-1. For
  encode-latency-bound workloads use `vaptvupt compress -l 1`/`-l 2`.
- **On a degenerate single-pattern input**, large-window extreme (L9)
  is slightly *worse* than L5/L7 — a known tradeoff of optimizing for
  real long-range matches. Doesn't affect realistic corpora.
- **On random / already-compressed data**, all codecs hit the
  incompressibility wall; the comparison degenerates to
  framing-overhead measurement.

### Security Test Results (v4.0.0 release)

Every release re-runs the full security regression matrix. These are
the v4.0.0 numbers:

| Test                            | Coverage                                                                 | Result            |
|---------------------------------|--------------------------------------------------------------------------|-------------------|
| F-06 HMAC tamper fuzz           | 2000 trials, single-bit flip in HMAC tag                                 | **0 silent accepts** / 2000 honest roundtrips OK |
| F-08 archive-integrity trailer  | Header/footer tamper detection                                           | **5/5 pass**      |
| F-09 byte-level integrity sweep | 1827 positions on a PQ-SDK archive, every byte flipped exhaustively      | **0/1827 silent accepts** ✓ |
| F-10 KDF default                | Argon2id is the default; PBKDF2 available via `--kdf pbkdf2`             | **10/10 pass**    |
| F-11 auth-fail wording          | Wrong-password vs tampered-archive messages are indistinguishable        | **12/12 pass**    |
| F-12 encrypted comments         | Comment block bound to per-block AAD; tamper rejected at extract        | **11/11 pass**    |
| F-15 KDF transparency           | Argon2id header self-describes its profile; back-compat + fail-closed   | **5/5 pass**      |
| Constant-time comparisons       | dudect Welch t-test (MAC tag + ML-KEM decaps); ~1% of leaky-memcmp + source-routing guard | **2/2 pass**      |
| Codec exact-size decode (OOB)   | 80 exact-`content_size` cases incl. BCJ payloads, ASan (codec 2.60.4 fix class) | **80/80 pass** |
| pq-box mode                     | roundtrips L1/L9/BCJ; wrong-key/key-confusion/tamper/cross-mode rejection | **13/13 pass** |
| NIST/RFC test vectors           | SHA-256, SHA-3, SHAKE-128, ML-KEM-768, AES-256-CTR (SP 800-38A), HMAC-SHA256, X25519, XXH64 | **16/16 pass** |
| Path-traversal                  | Absolute paths and `..` components refused                               | **5/5 pass**      |
| Block-swap                      | Re-ordered block detection                                                | **6/6 pass**      |
| Dedup property                  | Deduplication never produces wrong output                                 | **12/12 pass**    |
| Audit suite                     | Curated smoke tests                                                       | **10/10 pass**    |
| Argument-order                  | CLI flag ordering doesn't change semantics                               | **8/8 pass**      |
| Distro-safe `make check`        | Aggregate of the above (no flaky threading, no `make clean` mid-stream) | **91/91 pass**    |

Reproduce: `make check` (≈2 minutes, 91 assertions across 10 suites,
all green on x86_64 + aarch64). `make test` runs the full 15-suite
arc including dist reproducibility and packaging-syntax.

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
sudo vaptvupt disk backup backup.zupt /dev/sda1

# Clone with post-quantum encryption (strongest)
vaptvupt keygen -o mykey.key
vaptvupt keygen --pub -o pub.key -k mykey.key
sudo vaptvupt disk backup --pq pub.key backup.zupt /dev/nvme0n1p2

# Clone with password encryption
sudo vaptvupt disk backup -p backup.zupt /dev/sda1

# Maximum compression (level 9, extreme mode)
sudo vaptvupt disk backup -l 9 backup.zupt /dev/sda1

# Restore to a device or file
sudo vaptvupt disk restore backup.zupt /dev/sda1
sudo vaptvupt disk restore --pq mykey.key backup.zupt /dev/sda1
```

### How it works

```
Source device → Read 4MB blocks → Sparse detection → Compress → Encrypt → Write .zupt
                                      │                 │          │
                                      │                 │          └─ AES-256-CTR + HMAC-SHA256
                                      │                 └─ VaptVupt/LZHP (auto-selected)
                                      └─ Zero blocks stored as STORE (near-zero overhead)
```

VaptVupt reads the source device sequentially in 4MB chunks. Each block is checked for all-zero content (sparse detection uses 8-byte-wide comparison). Zero blocks are stored with codec `STORE` — effectively just the block header with no payload, saving both compression CPU time and archive space. Non-zero blocks are compressed with the selected codec and optionally encrypted. Per-block XXH64 checksums ensure byte-for-byte integrity on restore.

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

- **Unmount before backup** for filesystem consistency. For live systems, use LVM snapshots or filesystem freeze: `fsfreeze -f /mnt/data && vaptvupt disk backup ... && fsfreeze -u /mnt/data`.
- **Block devices require root** on Linux. Regular files (disk images, `.img`, `.raw`) do not.
- **Sparse-heavy disks** (freshly formatted, VMs with thin provisioning) compress extremely well — the sparse detector skips zero blocks at memory-copy speed with no compression overhead.
- **Verify after backup** with `vaptvupt test archive.zupt` — checks every block's XXH64 checksum without extracting.
- **PQ encryption for long-term** — disk backups stored for years should use `--pq` to resist future quantum attacks. Generate one keypair, store the private key offline, distribute the public key.
- **Restore is non-destructive on files** — writing to a regular file creates/overwrites it. Writing to a block device overwrites the raw device. Double-check the target path before restoring to a device.

### Comparison with other tools

| Feature | VaptVupt disk | dd + gzip | Clonezilla | partclone |
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

VaptVupt builds and runs on all major architectures. The Makefile auto-detects the platform and enables the best available features.

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

| Feature | VaptVupt v4.0 | gzip | zstd | 7-Zip |
|---------|-----------|------|------|-------|
| Default codec | VaptVupt/LZHP (auto) | DEFLATE | FSE+Huffman | LZMA2 |
| Full-disk backup | **`vaptvupt disk`** | — | — | — |
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
Verification:   5 Jasmin CT proofs, 19 ACSL contracts, 16 NIST/RFC test vectors
```

**Audit history:** Three internal audit sprints conducted on the 2.2.x line.
**14 bugs** found and fixed across the sprints — including one **HIGH-severity
Zip Slip path traversal** caught in the formal audit pass. Cumulative test
surface: **265 tests** (47 vaptvupt + 169 SDK + 49 inherited) plus **751,000
mutation-fuzz iterations** under ASAN/UBSAN, all passing. No external audit
yet — see SECURITY.md for honest scope.

See [SECURITY.md](SECURITY.md) for threat model. See [AUDIT.md](AUDIT.md) for
audit history. See [FORMAL_AUDIT_PROMPT.md](FORMAL_AUDIT_PROMPT.md) for the
methodology used in audit sprints.

---

## Usage

```
vaptvupt compress [OPTIONS] <output.zupt> <files/dirs...>
vaptvupt extract  [OPTIONS] <archive.zupt>
vaptvupt list     [OPTIONS] <archive.zupt>
vaptvupt test     [OPTIONS] <archive.zupt>
vaptvupt disk     backup [OPTIONS] <output.zupt> <device_or_file>
vaptvupt disk     restore [OPTIONS] <archive.zupt> <target>
vaptvupt bench    [--compare] <files/dirs...>
vaptvupt keygen   [-o file] [--pub] [-k privkey]
vaptvupt version
vaptvupt help
```

| Option | Description |
|--------|-------------|
| `-l <1-9>` | Compression level (default: 7) |
| `-t <N>` | Thread count (0=auto, 1=single, 2–64) |
| `-p [PW]` | Password encryption (PBKDF2 → AES-256) |
| `--pq <keyfile>` | Post-quantum hybrid encryption |
| `-o <DIR>` | Output directory (extract) |
| `-s` | Store without compression |
| `-f` | Fast LZ codec (VaptVupt-LZ) |
| `--vv` | Force VaptVupt codec |
| `--lzhp` | Force VaptVupt-LZHP codec |
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
vaptvupt bench ~/Documents/             # Per-level benchmark (levels 1-9)
vaptvupt bench --compare                # Cross-codec comparison (auto-generates corpus)
vaptvupt bench --compare ~/Documents/   # Compare codecs on your own data
```

---

## Codec Reference

| ID | Name | Algorithm | Default on | Override |
|----|------|-----------|------------|----------|
| `0x0010` | **VaptVupt** | LZ77 + tANS + AVX2/NEON SIMD | x86_64 (AVX2), aarch64 (NEON) | `--vv` |
| `0x000A` | **VaptVupt-LZHP** | LZ77 + Huffman + byte prediction | armhf, ppc64le, s390x, riscv64 | `--lzhp` |
| `0x0009` | VaptVupt-LZH | LZ77 + Huffman | — | — |
| `0x0008` | VaptVupt-LZ | Fast LZ77, 64KB window | — | `-f` |
| `0x0000` | Store | No compression | — | `-s` |

All codecs are forward-compatible: archives created with any codec can be read by any VaptVupt version that includes that codec, on any architecture. VaptVupt archives require VaptVupt v2.0+.

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
| v2.1.2 | Full-disk backup/restore (`disk` subcommand), sparse detection, all encryption modes, progress bar |
| v2.1.3 | LZHP prediction encoding fix (data corruption on structured data), shared write_enc_header, SOLID flag removed from disk, 78 tests |
| v2.1.4 | CodeQL: 4 security fixes — TOCTOU races eliminated (fstat on fd), X25519 scalar wipe via volatile |
| v2.1.5 | Block-level deduplication (`--dedup`), XXH64 fingerprint index, DEDUP_REF block type, 81 tests |
| v2.2.0–v2.2.2 | libzuptsdk 2.0 integration (HKDF-SHA3 combiner + key commitment + HPKE binding + Argon2id), `--pq-sdk` mode (XChaCha20-Poly1305 / AES-256-SIV), license-hygiene cleanup, full SPDX coverage |
| v2.2.3 | VaptVupt 2.48.2 codec integration: cost-aware lazy parser, 4-stream Huffman, `format_v2` flag (4–7% better binary), encoder memory hygiene (`vv_secure_zero` on free). Makefile arch-detection fix. ASAN/UBSAN clean across plain/password/PQ-SDK at all levels |
| v2.2.4–v2.2.5 | Audit sprint: findings F-01..F-07 closed, including F-06 (high) HMAC accept-on-disjoint-bits |
| v2.3.0–v2.3.1 | F-08/F-09 closed: archive-integrity trailer + preface-AAD MAC — exhaustive byte sweep 0/1827 undetected (format v1.5 → v1.6) |
| v2.4.x | Argon2id default KDF (F-10), error-message hygiene (F-11), encrypted archive comments (F-12), packaging arc (deb, RPM, AUR, Nix, Homebrew, openSUSE OBS), CI rewrite, THREAT_MODEL.md, manpage + shell completions, distro-safe `make check` |
| v3.0.0 | **Renamed Zupt → VaptVupt** (INPI Brasil trademark), VV codec 2.48.5, GUI binary-discovery fix. Wire format unchanged; `zupt` kept as compat symlink |
| v3.0.1–v3.0.3 | GUI license/version-parsing cleanup, F-13 (usage() literal size), static-analysis cleanup |
| v3.1.0 | Codec 2.48.5 → 2.53.3, decode over-copy fix |
| v3.2.0–v3.3.0 | SHA-256 hardware acceleration (Intel SHA-NI), incremental per-block HMAC (drops a malloc + full copy per block) |
| v3.4.0–v3.7.0 | F-15 KDF parameter transparency, measured constant-time MAC comparison (dudect), NIST SP 800-38A AES-CTR vectors, ML-KEM decaps routed through the audited CT primitive |
| v3.8.0 | Consolidated measured benchmarks + constant-time test robustness |
| **v4.0.0** | **Codec 2.60.4 security release (OOB heap write fixed in AVX2 decode fast path), `--pq-box` sealed-box mode (libpqvaptvupt 0.6.0, HKDF-SHA256 combiner), F-16 data-loss disclosure + fix (old in-tree BCJ encoder), CBMC-verified BCJ filters with auto ELF/PE/Mach-O detection, SHA-NI measured 5.8×. Wire format stays v1.6** |

See [CHANGELOG.md](CHANGELOG.md) for detailed per-version changes.

---

## License

VaptVupt is **dual-licensed**:

- **AGPL-3.0-or-later** — most of the codebase (CLI, libzuptsdk, GUI, Jasmin source). See [`LICENSE`](LICENSE).
- **GPL-3.0-or-later** — the VaptVupt LZ codec only (`src/vv_*.c`, `src/vaptvupt_api.c` and headers). VaptVupt is GPL so it can be considered for upstreaming into the Linux/BSD kernels.
- **Commercial license** available for relief from AGPL/GPL terms. Contact `sac@securityops.co`.

Every source file carries an explicit SPDX header. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for full attribution. VaptVupt contains **no third-party source code** — every line is original work.

Security vulnerabilities: see [SECURITY.md](SECURITY.md).

## Related projects

All by Cristian Cezar Moisés, hosted on git.securityops.co:

- [vaptvupt](https://git.securityops.co/cristiancmoises/vaptvupt) — this repo (CLI + GUI)
- [zupt-android](https://git.securityops.co/cristiancmoises/zupt-android) — Android port
- [zupt-web](https://git.securityops.co/cristiancmoises/zupt-web) — Web frontend
- [libvuptsdk](https://git.securityops.co/cristiancmoises/libvuptsdk) — Standalone C SDK
- [vaptvupt-codec](https://git.securityops.co/cristiancmoises/vaptvupt-codec) — Standalone LZ + tANS codec

## Support the Project
If you find VaptVupt useful, please consider sharing it or contributing — see the README footer for contact links.

---
© 2026 Cristian Cezar Moisés — [git.securityops.co/cristiancmoises](https://git.securityops.co/cristiancmoises)
