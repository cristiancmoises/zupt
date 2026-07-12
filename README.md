<!-- Logo: rehost on git.securityops.co/cristiancmoises/vaptvupt or zupt.securityops.co; old GitHub user-attachments URL no longer in use -->
<!-- <img width="493" height="173" alt="logo" src="https://zupt.securityops.co/assets/logo.png"/> -->

# VaptVupt

Backup compression with hardware-adaptive codec selection, AES-256
authenticated encryption, post-quantum key encapsulation, and full-disk
backup. Pure C11, ~13,000 lines. Builds and runs on x86_64, aarch64,
armhf, ppc64le, s390x, and riscv64.

License: AGPL-3.0-or-later (dual-licensed AGPL + commercial).

> **Renamed from "Zupt" in v3.0.0** because of a prior INPI Brasil
> trademark registration on the name "Zupt" for unrelated software.
> The `.zupt` archive extension and `ZUPT` header magic bytes are
> unchanged — v2.x and v3.0.0 archives remain compatible. The `zupt`
> command is preserved as a symlink to `vaptvupt` for one major version
> cycle.

## What's new in 5.1.0

- **Codec upgraded to VaptVupt 2.65.0** (from 2.60.4). Same on-disk format
  (`.zupt` v1.6, fully interoperable both directions — a 5.0.0 binary reads
  5.1.0 archives and vice-versa), a much faster balanced encoder, and the
  extreme-mode literal-pricing work from codec Sprints 124–130.
- **Big compression-ratio gains — two long-standing settings were leaving most
  of the codec's ratio on the table.** The `.zupt` wrapper (1) *forced* the
  binary-oriented `format_v2` path on every input, which halved the optimal
  parser's ratio on text, and (2) capped the extreme block at 512 KiB, so the
  "large-window extreme" parser could never see past it. Both are fixed:
  `format_v2` is now auto-detected (binary gets it, text keeps the optimal
  parser) and block size scales with level. Measured, level 9 (extreme):

  | Data class | 5.0.0 | 5.1.0 |
  |---|--:|--:|
  | Text (docs/markdown) | 3.77× | **5.98×** |
  | Server logs | 7.21× | **9.07×** |
  | JSON | 8.25× | **9.38×** |
  | Source code | 4.93× | **5.63×** |

  Extreme mode trades encode speed for this (its optimal DP now runs over a
  larger window); balanced (the default, `-l 7`) also improves and stays fast.
  `--dedup` automatically keeps a small block so block-level dedup still works.
  See the [full comparison tables](#compression-comparison) below.
- **GUI: fixed "the app closes / gets stuck when I compress."** Three separate
  defects: the worker thread was garbage-collected while still running (crash on
  every job completion); on Wayland the window never mapped (now falls back to
  XWayland automatically); and the CLI's live progress (`\r` frames) was never
  parsed, so the GUI looked frozen on any file larger than one block — it now
  drives the progress bar. Added `vaptvupt-gui --selftest` for headless launch
  verification.
- No key/format change: `--pq` / `--pq-only` keys and archives from 5.0.0 keep
  working. (The 5.0.0 FIPS 203 KEM change below is unchanged.)

Binaries for the CLI (5.1.0) and GUI (5.1.0) are on the
[release page](https://git.securityops.co/cristiancmoises/vaptvupt/releases/tag/v5.1.0).

---

## What's new in 5.0.0

- **Genuine FIPS 203 ML-KEM-768 — validated against OpenSSL.** Earlier releases
  shipped round-3 CRYSTALS-Kyber under a "FIPS 203" label; it was secure but
  **not interoperable** with a compliant ML-KEM. Three deviations (a transposed
  matrix-`Â` sampling convention, the round-3 KDF, and the implicit-rejection
  domain) are fixed, and the result is now **byte-for-byte interoperable with
  OpenSSL 3.5's FIPS 203 ML-KEM-768** in both directions — checked on every
  `make check` (`tests/test_mlkem_fips203.sh`). Hybrid `--pq` (ML-KEM-768 +
  X25519) remains the recommended flagship; `--pq-only` is pure ML-KEM-768.
- **⚠ Breaking:** because the KEM math changed, `--pq`/`--pq-only` **keys and
  archives from ≤ 4.2.1 no longer decrypt** — regenerate keys and re-encrypt.
  Password mode (`-p`) and plain compression are unaffected; wire format is still v1.6.
- **CLI security fixes.** A `compress -p out.zupt file1 file2` **data-loss** bug
  (the archive name was eaten as the password and overwrote `file1`) and a
  `compress out.zupt dir -p pw` **silent-plaintext** bug are both guarded now; a
  **heap OOB read** in the AVX2 decoder on crafted archives is bounded; banners
  report the build's real KDF.
- **GUI reworked so it actually works.** It used to default every encryption
  path to SDK modes absent from the source-only build (key generation failed out
  of the box). Now a build-aware Hybrid/Full-PQ selector, PQ-key auto-detect on
  Extract/Verify, and About/threading fixes.
- **Cross-platform.** A portable GUI package (Windows/macOS/Linux/BSD, needs
  Python + PySide6) and a CI workflow that builds native Windows `.exe`/installer
  and macOS `.dmg` on real runners.

> **F-16 (data loss):** archives created by **≤ 3.8.0** at `-l 8`/`-l 9`
> whose inputs included x86/ELF/PE executables may be **undecodable by any
> version** (write-time defect in the old in-tree BCJ encoder). Re-create
> such archives with 5.0.0 and verify extraction before deleting source
> data. Details in [CHANGELOG.md](CHANGELOG.md).

Binaries for the CLI (5.0.0) and GUI (5.0.0) are on the
[release page](https://git.securityops.co/cristiancmoises/vaptvupt/releases/tag/v5.0.0).

---

<a name="compression-comparison"></a>
## Compression comparison

Single-thread, one 20–25 MB file per data class, best-of-run on an x86-64 AVX2 machine (codec 2.65.0). Ratio = original ÷ compressed — higher is better. Reproduce with `vaptvupt -b <file>` and the standard `zstd` / `gzip` / `lz4` CLIs. Numbers vary with data and hardware.

### Ratio vs other compressors

VaptVupt at level 9 (extreme) and level 7 (balanced — the default), against zstd, gzip and lz4.

| Data class | VaptVupt -9 | VaptVupt -7 | zstd -9 | zstd -3 | gzip -9 | lz4 -9 |
|---|--:|--:|--:|--:|--:|--:|
| Text (docs, Markdown) | **5.98×** | 4.08× | 6.18× | 4.95× | 3.75× | 3.28× |
| Source code (C / headers) | **5.63×** | 4.90× | 5.81× | 4.96× | 5.00× | 4.17× |
| JSON (structured records) | **9.38×** | 6.53× | 8.21× | 7.28× | 7.60× | 4.94× |
| Server logs | **9.07×** | 6.64× | 8.15× | 6.89× | 7.25× | 5.19× |
| Binaries (.so / ELF) | **1.00×** | 1.00× | 1.01× | 1.00× | 1.01× | 1.00× |
| Incompressible (random) | **1.00×** | 1.00× | 1.00× | 1.00× | 1.00× | 1.00× |

### This release vs the previous one (5.0.0 → 5.1.0)

Same tool, level 9 — the gain is auto-`format_v2` plus the larger extreme window.

| Data class | 5.0.0 | 5.1.0 | Change |
|---|--:|--:|--:|
| Text (docs, Markdown) | 3.77× | **5.98×** | +58% |
| Source code (C / headers) | 4.93× | **5.63×** | +14% |
| JSON (structured records) | 8.25× | **9.38×** | +14% |
| Server logs | 7.21× | **9.07×** | +26% |
| Binaries (.so / ELF) | 1.01× | **1.00×** | -1% |
| Incompressible (random) | 1.00× | **1.00×** | +0% |

### Throughput (MB/s, single thread)

The CLI multi-threads compression with `-t 0` (auto); decompression is single-thread and level-independent. Extreme (`-9`) spends CPU for the smallest archive — use the default `-7` for everyday backups.

| Data class | -7 comp | -7 decomp | -9 comp | -9 decomp | zstd-9 comp |
|---|--:|--:|--:|--:|--:|
| Text (docs, Markdown) | 80 | 181 | 2 | 214 | 42 |
| Source code (C / headers) | 92 | 167 | 1 | 214 | 35 |
| JSON (structured records) | 95 | 162 | 1 | 195 | 35 |
| Server logs | 111 | 192 | 1 | 189 | 34 |

---

## Features

- **Hardware-adaptive codec** — auto-detects AVX2/NEON at runtime and
  selects the codec: VaptVupt (LZ77 + tANS + SIMD decode) on capable
  hardware, VaptVupt-LZHP on everything else. Override with `--vv` or
  `--lzhp`.
- **Post-quantum encryption** — `--pq` uses ML-KEM-768 + X25519 hybrid
  KEM (the approach used by Signal and iMessage), protecting against
  "harvest now, decrypt later" attacks. `--pq-only` offers a full (pure)
  ML-KEM-768 mode with no classical component for "PQ-only" compliance
  postures. Both are in-tree and available in the default build; hybrid
  `--pq` is the recommended default.
- **AES-NI acceleration** — AES-256-CTR via Jasmin-verified assembly with
  a 4-block interleaved pipeline. AVX detection validates OSXSAVE/XCR0 (no
  SIGILL). Falls back to C table-based AES on unsupported hardware.
- **SHA-NI acceleration** — HMAC-SHA256 (the Encrypt-then-MAC pass) and
  PBKDF2 use the Intel SHA-NI compression path when the CPU supports it
  (Intel Goldmont+/Ice Lake+, AMD Zen+), selected at runtime via CPUID.
  Bit-identical output; scalar C fallback elsewhere. `vaptvupt version`
  prints the acceleration set for your CPU.
- **Incremental HMAC** — the per-block MAC streams its segments through an
  incremental HMAC-SHA256 instead of copying each block's ciphertext into
  a temporary buffer, removing a per-block heap allocation and full-payload
  copy on encrypt and decrypt with a byte-for-byte identical MAC (RFC 2104).
- **Multi-threaded** — compression and decompression both parallelized.
  `-t 0` auto-detects cores.
- **Full-disk backup** — `vaptvupt disk backup` clones disks or partitions
  in one command. Sparse block detection skips zero regions; all encryption
  modes supported; restore verifies per-block XXH64 checksums.
- **Per-block integrity** — XXH64 checksum + HMAC-SHA256 per block. Wrong
  password rejected immediately.
- **Self-describing KDF** — password archives record their key-derivation
  profile in the authenticated header, so an archive carries the parameters
  needed to open it later. Unknown profiles are refused fail-closed rather
  than mis-derived. Default is PBKDF2-SHA256 (600K iterations); Argon2id is
  available in a `WITH_SDK=1` build.
- **Constant-time comparisons** — every security-critical comparison (HMAC
  tag, archive-integrity trailer, ML-KEM-768 implicit-rejection check)
  routes through a single primitive (`zupt_ct_memeq`, branch-free, volatile
  accumulator, length-independent), checked by a dudect-style Welch t-test
  in CI.
- **Formally verified crypto** — 5 Jasmin assembly functions with
  constant-time proofs; 19 ACSL-annotated functions for Frama-C memory
  safety analysis.
- **Multi-architecture** — builds on x86_64, aarch64, armhf, ppc64le,
  s390x, riscv64. Jasmin CT crypto on x86_64, C fallback everywhere else.
  Any archive decompresses on any architecture.
- **No external dependencies (default build)** — ML-KEM, X25519, Keccak,
  SHA-256, AES-256, HMAC, PBKDF2 and the VaptVupt codec are all pure C11.
  Builds with `gcc` or `cl` alone.

---

## Quick Start

### Build & install
```
git clone https://git.securityops.co/cristiancmoises/vaptvupt.git && \
cd vaptvupt && \
make && \
sudo make install
```

The default build needs only a C compiler and `make` (plus libm/pthread).
`make WITH_SDK=1` additionally links the separately distributed
`libzuptsdk`/`libpqvaptvupt` to enable `--pq-sdk`, `--pq-box`, and the
Argon2id KDF.

### Pre-built packages

Assets are published on the
[v5.1.0 release page](https://git.securityops.co/cristiancmoises/vaptvupt/releases/tag/v5.1.0)
and verifiable against the published `SHA256SUMS.txt`.

**Command-line tool (`vaptvupt` 5.1.0):**

| Format | File | Distros |
|---|---|---|
| Debian/Ubuntu | `vaptvupt_5.1.0_amd64.deb` | Debian 11+, Ubuntu 22.04+, Mint 21+ |
| RPM | `vaptvupt-5.1.0-1.x86_64.rpm` | Fedora 38+, RHEL 9+, openSUSE, AlmaLinux, Rocky, other RPM-based distributions |
| AppDir tarball | `vaptvupt-5.1.0-x86_64.AppDir.tar.gz` | Any glibc 2.28+ (extract & run, no FUSE) |
| Source tarball | `vaptvupt-5.1.0.tar.gz` | Build from source on any platform |
| openSUSE OBS | `vaptvupt-5.1.0-opensuse-obs.tar.gz` | Open Build Service source bundle |

**Graphical front-end (`vaptvupt-gui` 5.1.0):**

| Format | File | Distros |
|---|---|---|
| Debian/Ubuntu | `vaptvupt-gui_5.1.0_all.deb` | Debian 11+, Ubuntu 22.04+, Mint 21+ |
| RPM | `vaptvupt-gui-5.1.0-1.noarch.rpm` | RPM-based distributions |
| AppImage | `VaptVupt-GUI-5.1.0-x86_64.AppImage` | Any glibc 2.28+ (single-file, no install) |
| AppDir tarball | `VaptVupt-GUI-5.1.0-x86_64.AppDir.tar.gz` | Any glibc 2.28+ (extract & run) |

**Windows / macOS / BSD:**

| Platform | File | Notes |
|---|---|---|
| Windows | `VaptVupt-Setup-5.1.0.exe`, `vaptvupt-gui-5.1.0-windows-x86_64.exe`, `vaptvupt-5.1.0-windows-x86_64.exe` | Native installer + standalone GUI + CLI, built on a Windows runner by CI |
| macOS | `VaptVupt-5.1.0.dmg`, `vaptvupt-5.1.0-macos` | `.dmg` GUI bundle + CLI, built on a macOS runner by CI |
| Any OS (portable GUI) | `vaptvupt-gui-5.1.0-portable.zip` | Python GUI + launchers for Windows/macOS/Linux/BSD; needs Python 3.8+ and PySide6 (or PyQt6), plus the `vaptvupt` CLI on PATH |
| BSD / others | `vaptvupt-5.1.0.tar.gz` | Build the CLI from source (`make`); run the portable GUI |

The native Windows/macOS installers are produced by the project's CI
(`.github/workflows/cross-platform.yml`) on real Windows and macOS runners — see
the GitHub release. The portable GUI package runs the same GUI everywhere Python
and Qt are available.

```bash
# Verify downloads first
sha256sum -c SHA256SUMS.txt

# Debian / Ubuntu / Mint
sudo dpkg -i vaptvupt_5.1.0_amd64.deb
sudo apt-get install -f       # resolve any missing deps

# Fedora / RHEL / openSUSE / AlmaLinux / Rocky and other RPM-based distros
sudo rpm -i vaptvupt-5.1.0-1.x86_64.rpm
# or
sudo dnf install ./vaptvupt-5.1.0-1.x86_64.rpm

# AppDir tarball (no install, no FUSE required)
tar xzf vaptvupt-5.1.0-x86_64.AppDir.tar.gz
./vaptvupt-5.1.0-x86_64.AppDir/AppRun --help

# GUI AppImage (single executable)
chmod +x VaptVupt-GUI-5.1.0-x86_64.AppImage
./VaptVupt-GUI-5.1.0-x86_64.AppImage
```

### Building from SRPM (Fedora / RHEL / RPM-based distributions)

```bash
tar xzf vaptvupt-5.1.0.srpm.tar.gz
cd ~/rpmbuild  # or use rpmbuild --define "_topdir $(pwd)"
rpmbuild -bb SPECS/vaptvupt.spec
sudo rpm -i RPMS/x86_64/vaptvupt-5.1.0-1.*.rpm
```

### Basic usage

```bash
# Compress a directory (auto-selects codec for your hardware)
vaptvupt compress backup.zupt ~/Documents/

# Compress at a specific level (1=fast, 5=balanced, 9=extreme)
vaptvupt compress -l 9 backup.zupt ~/Documents/

# Force the VaptVupt codec (default on AVX2/NEON hardware)
vaptvupt compress --vv -l 5 backup.zupt ~/Documents/

# Multi-threading (-t 0 = auto-detect cores)
vaptvupt compress -t 0 -l 5 backup.zupt ~/Documents/

# Password encryption (AES-256-CTR + HMAC-SHA256, PBKDF2-SHA256 KDF)
vaptvupt compress -p "my-strong-password" backup.zupt ~/Documents/

# List archive contents
vaptvupt list backup.zupt

# Show archive metadata (no password needed)
vaptvupt info backup.zupt

# Verify archive integrity (HMAC + per-block checksums)
vaptvupt test backup.zupt
vaptvupt test -p "my-strong-password" backup.zupt

# Extract
vaptvupt extract -o ~/restored/ backup.zupt
vaptvupt extract -p "my-strong-password" -o ~/restored/ backup.zupt

# Benchmark all 9 levels on a file
vaptvupt bench big-file.tar
```

#### Post-quantum encryption

```bash
# Native --pq (ML-KEM-768 + X25519 hybrid KEM, in-tree, default build).
# Recommended for new archives.
vaptvupt keygen -o mykey.key
vaptvupt keygen --pub -o pub.key -k mykey.key
vaptvupt compress --pq pub.key backup.zupt ~/Documents/
vaptvupt extract  --pq mykey.key -o ~/restored/ backup.zupt

# Native --pq-only (full/pure ML-KEM-768, no classical component).
# Use only for "PQ-only" compliance postures; --pq (hybrid) is safer.
vaptvupt keygen --pq-only -o pqkey
vaptvupt keygen --pub --pq-only -o pqkey.pub -k pqkey
vaptvupt compress --pq-only pqkey.pub backup.zupt ~/Documents/
vaptvupt extract  --pq-only pqkey -o ~/restored/ backup.zupt
```

The SDK-backed modes below require a `make WITH_SDK=1` build linked against
the separately distributed `libzuptsdk`/`libpqvaptvupt`:

```bash
# --pq-sdk (HKDF combiner + key commitment + HPKE binding + Argon2id)
vaptvupt keygen --sdk -o mykey.priv     # writes mykey.priv and mykey.priv.pub
vaptvupt compress --pq-sdk mykey.priv.pub backup.zupt ~/Documents/
vaptvupt extract  --pq-sdk mykey.priv -o ~/restored/ backup.zupt

# --pq-box sealed-box (ML-KEM-768 + X25519 via HKDF-SHA256 combiner)
vaptvupt keygen --box -o box.key                       # writes box.key + box.key.pub
vaptvupt compress --pq-box box.key.pub backup.zupt ~/Documents/
vaptvupt extract  --pq-box box.key -o ~/restored/ backup.zupt
```

#### Full-disk backup

```bash
# Backup a disk or partition (sparse-detection skips zero regions)
sudo vaptvupt disk backup -l 5 disk.zupt /dev/sda

# With encryption
sudo vaptvupt disk backup -p "passphrase" -l 5 disk.zupt /dev/sda

# Restore (writes raw bytes back to a block device or file)
sudo vaptvupt disk restore disk.zupt /dev/sdb
sudo vaptvupt disk restore -p "passphrase" disk.zupt /dev/sdb

# Backup a partition image file (no root needed)
vaptvupt disk backup -l 5 part.zupt /path/to/partition.img
```

---

## Auto Codec Detection

VaptVupt selects the compression codec based on your hardware (since
v2.0.0). No flags needed — `vaptvupt compress` picks the fastest option
available.

| Architecture | SIMD Available | Default Codec | Decode Throughput |
|---|---|---|---|
| x86_64 + AVX2 | AVX2 inline SIMD | VaptVupt | ~2–3 GB/s |
| x86_64 (no AVX2) | Scalar | VaptVupt-LZHP | ~500 MB/s |
| aarch64 + NEON | NEON SIMD | VaptVupt | ~1–2 GB/s |
| armhf, ppc64le, s390x, riscv64 | Scalar | VaptVupt-LZHP | ~300–500 MB/s |

Decompression is universal. An archive created with VaptVupt on x86_64
extracts on aarch64 (NEON or scalar decode) and vice versa. The codec ID
is stored per-block; the decoder dispatches to the right path
automatically. Override with `--vv` or `--lzhp`.

---

## VaptVupt Codec

VaptVupt combines LZ77 dictionary matching with tANS (table-based
Asymmetric Numeral Systems) entropy coding and SIMD-accelerated
decompression.

This release embeds VaptVupt codec 2.65.0 (from the
[vaptvupt-codec](https://git.securityops.co/cristiancmoises/vaptvupt-codec)
repository, tag v2.65.0). Over the previous 2.60.4 it adds a faster balanced
encoder and the Sprint 124–130 extreme-mode literal-pricing improvements. Two
in-tree audit patches ride on top of the vendored source (an ANS decode
safe-zone reserve and an AVX2 offset-read bound). See [CHANGELOG.md](CHANGELOG.md).

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

### Modes

| Mode | CLI | Chain Depth | Entropy | Use Case |
|------|-----|-------------|---------|----------|
| Ultra-Fast | `-l 1` to `-l 2` | 4 | None | Speed priority, streaming |
| Balanced | `-l 3` to `-l 7` (default) | 48 | 4-way ANS | General backup data |
| Extreme | `-l 8` to `-l 9` | 256 | Order-1 context ANS + cost-aware lazy parser | Maximum compression |

The wrapper leaves the codec's `format_v2` flag on **auto**: since codec
v2.61.0 the encoder enables the `T`-tag / min_match=3 path for binary-detected
input on its own and keeps the optimal `S` parser for text. (Forcing it, as
5.0.0 did, routed text through the binary path and roughly halved the
extreme-mode text ratio.) Block size scales with level so the extreme parser
gets a real window (see [`auto_block_size`](src/zupt_format.c)); `--dedup`
overrides that with a small block so block-level deduplication still finds
duplicates.

### Measured benchmark

Head-to-head ratio and throughput against zstd / gzip / lz4 are in the
[Compression comparison](#compression-comparison) section above (codec 2.65.0,
this release). Reproduce any cell with `vaptvupt -b <file>`.

Reading those numbers:

- On ratio VaptVupt-9 **wins outright on logs and JSON** and is within a few
  percent of `zstd -19`-class output on text and source. `zstd` still
  *compresses* faster; VaptVupt *decodes* 2–4× faster than it compresses.
- Encode throughput is the tradeoff. The optimal parser and hash-chain walk
  that win ratio cost encode speed; extreme (`-l 8`/`-l 9`) is the
  "spend CPU for the smallest archive" setting. For everyday backups use the
  default balanced `-l 7` (fast and still a strong ratio); for
  encode-latency-bound workloads use `-l 1`/`-l 2`.
- On random / already-compressed data, all codecs hit the
  incompressibility wall.

### Security regression tests

Every release re-runs the security regression matrix (`make check`,
≈2 minutes on x86_64 and aarch64). It covers:

- HMAC single-bit tamper detection and honest roundtrips.
- Archive-integrity trailer (header/footer tamper detection).
- Byte-level integrity sweep on a PQ archive (every byte flipped).
- KDF default (PBKDF2-SHA256) and self-describing header transparency,
  with back-compat and fail-closed on unknown profiles.
- Indistinguishable wrong-password vs tampered-archive error messages.
- Encrypted comment block bound to per-block AAD.
- Constant-time comparison (dudect Welch t-test on MAC tag and ML-KEM
  decaps) plus a source-routing guard.
- Codec exact-`content_size` decode cases (incl. BCJ payloads) under ASan.
- NIST/RFC test vectors: SHA-256, SHA-3, SHAKE-128, ML-KEM-768,
  AES-256-CTR (SP 800-38A), HMAC-SHA256, X25519, XXH64.
- Path-traversal refusal, block-swap detection, deduplication correctness,
  and CLI argument-order invariance.

`make test` runs the full suite including dist reproducibility and
packaging-syntax checks.

### Codec notes

- **tANS entropy** — asymptotically optimal coding with single-instruction
  decode per symbol (vs Huffman's multi-step tree walk).
- **4-way interleaved ANS** — decodes 4 symbols per bitstream refill cycle.
- **4-stream Huffman literal coding** (`lit_fmt=4`) — improves ratio on
  structured data.
- **AVX2/NEON SIMD decode** — inline 32-byte copies with tiered offset
  handling. Scalar fallback on unsupported hardware.
- **Rep-match** — checks 3 recent offsets before the hash probe (O(1) vs
  O(chain_depth)), hitting ~30% of matches.
- **Order-1 context model** — captures byte-pair correlations in structured
  data (JSON, CSV, logs).
- **Cost-aware lazy parser** — puts Extreme mode ahead of zstd-3 in
  aggregate ratio.
- **Adaptive window** — trial-compresses at wlog=16 vs wlog=20, picking the
  larger window only if ≥3% improvement.
- **`format_v2`** (T-tag, min_match=3) — 4–7% better binary ratio;
  transparent to v2.33.0+ decoders.
- **Memory hygiene** — encoder working buffers scrubbed via
  `vv_secure_zero` before `free()`.
- **~6,500 lines** of pure C11.

---

## Post-Quantum Encryption

VaptVupt has two native PQ modes, both in-tree and available in the default
build.

**`--pq` — hybrid ML-KEM-768 + X25519 (envelope `0x02`, recommended):**

```
Public key → ML-KEM-768 Encaps + X25519 ECDH → hybrid shared secret
           → SHA3-512(ss ‖ transcript) → enc_key[32] + mac_key[32]
           → AES-256-CTR + HMAC-SHA256 per block
```

Security model: secure if **EITHER** ML-KEM-768 (post-quantum) **OR** X25519
(classical) is secure. This is the recommended default — it stays safe even
if one primitive is later broken.

**`--pq-only` — full/pure ML-KEM-768 (envelope `0x06`):**

```
Public key → ML-KEM-768 Encaps → shared secret ss, ciphertext ct
           → archive_key = SHA3-512(ss ‖ ct ‖ "ZUPT-PQ-ONLY-v1")
           → AES-256-CTR + HMAC-SHA256 per block
```

Security model: secure if ML-KEM-768 is secure — there is **no classical
fallback**. Choose this only when a policy mandates a single NIST-standardised
PQ primitive with no classical KEM in the envelope (CNSA 2.0-style "PQ-only").
The trade-off is explicit: a future break of ML-KEM-768 *alone* breaks the
archive, whereas under `--pq` the attacker must also break X25519. **When in
doubt, use `--pq`.**

Password mode (`-p`) is not quantum-safe. Use `--pq` (or `--pq-only`) for
long-term protection.

The SDK-backed `--pq-sdk` and `--pq-box` modes are optional and require a
`make WITH_SDK=1` build against `libzuptsdk`/`libpqvaptvupt`.

---

## Full-Disk Backup

Clone disks, partitions, or raw images with compression and encryption in
one command.

### Quick start
```bash
# Clone a partition (requires read access)
sudo vaptvupt disk backup backup.zupt /dev/sda1

# Clone with post-quantum encryption
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

VaptVupt reads the source device sequentially in 4MB chunks. Each block is
checked for all-zero content (8-byte-wide comparison). Zero blocks are
stored with codec `STORE` — effectively just the block header with no
payload. Non-zero blocks are compressed with the selected codec and
optionally encrypted. Per-block XXH64 checksums ensure byte-for-byte
integrity on restore.

### Best practices

Encryption modes:

| Mode | Command | Security Level | Speed Impact |
|------|---------|---------------|-------------|
| PQ Hybrid | `--pq pub.key` | Quantum-resistant + classical | ~5% overhead |
| Password | `-p` | AES-256, PBKDF2-SHA256 600K iter | ~3% overhead |
| None | (default) | Integrity only (XXH64) | Fastest |

Compression levels for disks:

| Level | Mode | Best for | Typical ratio |
|-------|------|----------|--------------|
| `-l 1` to `-l 3` | Ultra-Fast | Live systems, NVMe (speed priority) | 1.5–2.5:1 |
| `-l 4` to `-l 7` | Balanced (default) | General partitions, ext4/NTFS | 2–5:1 |
| `-l 8` to `-l 9` | Extreme | Cold storage, archival backups | 3–10:1 |

Operational guidance:

- Unmount before backup for filesystem consistency. For live systems use
  LVM snapshots or filesystem freeze:
  `fsfreeze -f /mnt/data && vaptvupt disk backup ... && fsfreeze -u /mnt/data`.
- Block devices require root on Linux. Regular files (disk images, `.img`,
  `.raw`) do not.
- Sparse-heavy disks compress well — the sparse detector skips zero blocks
  at memory-copy speed with no compression overhead.
- Verify after backup with `vaptvupt test archive.zupt` — checks every
  block's XXH64 checksum without extracting.
- For long-term disk backups use `--pq`. Generate one keypair, store the
  private key offline, distribute the public key.
- Restore is non-destructive on files (creates/overwrites the file);
  writing to a block device overwrites the raw device. Double-check the
  target path before restoring to a device.

---

## Multi-Architecture Support

The Makefile auto-detects the platform and enables the best available
features.

| Feature | x86_64 | aarch64 | armhf | ppc64le | s390x | riscv64 |
|---------|--------|---------|-------|---------|-------|---------|
| Jasmin CT crypto | yes | C fallback | C fallback | C fallback | C fallback | C fallback |
| AES-NI hardware | yes (with AVX) | — | — | — | — | — |
| AVX2 SIMD decode | yes | — | — | — | — | — |
| NEON SIMD decode | — | yes | — | — | — | — |
| Default codec | VaptVupt | VaptVupt | LZHP | LZHP | LZHP | LZHP |
| All codecs decode | yes | yes | yes | yes | yes | yes |

Build for packaging (PIE, hardening flags):
```bash
make CFLAGS="-Wall -Wextra -O2 -std=c11 -fPIE -Iinclude -Isrc" LDFLAGS="-pie -Wl,-z,relro,-z,now"
make install DESTDIR=/buildroot
```

---

## Security

```
Password mode:  Password → PBKDF2-SHA256 (600K iter) → enc_key + mac_key
PQ hybrid mode: Public key → ML-KEM-768 Encaps + X25519 ECDH → enc_key + mac_key
Per-block:      AES-256-CTR(enc_key, nonce ⊕ seq) + HMAC-SHA256(mac_key)
Key protection: mlock() prevents swap, buffer canaries detect overflow
Timing:         Always-decrypt mitigation (no timing oracle on MAC failure)
AES dispatch:   AVX+AES-NI check with OSXSAVE/XCR0 (no SIGILL on any CPU)
Path safety:    Zip Slip / symlink defenses (zupt_path_is_safe + O_NOFOLLOW)
Verification:   5 Jasmin CT proofs, 19 ACSL contracts, 16 NIST/RFC test vectors
```

The `WITH_SDK=1` build adds an HKDF-SHA3 combiner with domain separation,
key commitment, and HPKE binding for the `--pq-sdk`/`--pq-box` modes, plus
the Argon2id KDF.

Internal audit passes on the 2.2.x line fixed 14 bugs, including a
HIGH-severity Zip Slip path traversal. There has been no external audit.
See [SECURITY.md](SECURITY.md) for the threat model and honest scope, and
[FORMAL_AUDIT_PROMPT.md](FORMAL_AUDIT_PROMPT.md) for the audit methodology.

Report security vulnerabilities per [SECURITY.md](SECURITY.md).

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
| `-p [PW]` | Password encryption (PBKDF2-SHA256 → AES-256) |
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
make                        # Default build: C compiler + make only
make WITH_SDK=1             # Link libzuptsdk/libpqvaptvupt: --pq-sdk, --pq-box, Argon2id
make V=1                    # Verbose build output
make test-all               # Regression + NIST + VV + MT + PQ + disk
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
| `0x0010` | VaptVupt | LZ77 + tANS + AVX2/NEON SIMD | x86_64 (AVX2), aarch64 (NEON) | `--vv` |
| `0x000A` | VaptVupt-LZHP | LZ77 + Huffman + byte prediction | armhf, ppc64le, s390x, riscv64 | `--lzhp` |
| `0x0009` | VaptVupt-LZH | LZ77 + Huffman | — | — |
| `0x0008` | VaptVupt-LZ | Fast LZ77, 64KB window | — | `-f` |
| `0x0000` | Store | No compression | — | `-s` |

All codecs are forward-compatible: archives created with any codec can be
read by any VaptVupt version that includes that codec, on any architecture.
VaptVupt archives require VaptVupt v2.0+.

---

## Release History

| Version | Description |
|---------|-------------|
| v0.1–v0.6 | LZ77 compression, AES-256 encryption, multi-threading |
| v0.7 | Post-quantum hybrid encryption (ML-KEM-768 + X25519) |
| v1.0 | Stable release — format frozen v1.4, security audit |
| v1.1–v1.5.5 | X25519 fix, NIST vectors, CPUID detection, Jasmin CT assembly linked, build-system improvements |
| v2.0 | VaptVupt codec, auto hardware detection, all 5 Jasmin wired, AVX SIGILL fix, ACSL, mlock, fuzzing, canaries, AES-NI pipeline, MT decompress, multi-arch (6 arches), `--lzhp` |
| v2.1.x | Cross-block dictionary carry, Termux/Android build fix, full-disk backup/restore, LZHP fix, CodeQL fixes, block-level deduplication |
| v2.2.x | libzuptsdk integration (`--pq-sdk`), VaptVupt 2.48.2 codec (cost-aware lazy parser, 4-stream Huffman, `format_v2`), audit findings F-01..F-07 closed (incl. F-06 high) |
| v2.3.x | F-08/F-09 closed: archive-integrity trailer + preface-AAD MAC (format v1.5 → v1.6) |
| v2.4.x | PBKDF2/Argon2id KDF work (F-10), error-message hygiene (F-11), encrypted comments (F-12), packaging arc (deb/RPM/AUR/Nix/Homebrew/OBS), THREAT_MODEL.md, manpage + completions, distro-safe `make check` |
| v3.0.x | Renamed Zupt → VaptVupt (INPI Brasil trademark), VV codec 2.48.5, GUI fixes, F-13 fix. Wire format unchanged; `zupt` kept as compat symlink |
| v3.1.0–v3.3.0 | Codec 2.48.5 → 2.53.3, decode over-copy fix, SHA-256 hardware acceleration (Intel SHA-NI), incremental per-block HMAC |
| v3.4.0–v3.8.0 | F-15 KDF parameter transparency, measured constant-time MAC comparison (dudect), NIST SP 800-38A AES-CTR vectors, ML-KEM decaps through the CT primitive, consolidated benchmarks |
| v4.0.0 | Codec 2.60.4 security release (OOB heap write fixed in AVX2 decode fast path), `--pq-box` sealed-box mode, F-16 data-loss disclosure + fix (old in-tree BCJ encoder), CBMC-verified BCJ filters with auto ELF/PE/Mach-O detection, SHA-NI acceleration. Wire format v1.6 |
| v4.1.0 | Source-only tree (prebuilt libzuptsdk/libpqvaptvupt removed); default build needs only a C compiler + make; native `--pq` is the default PQ mode; `--pq-sdk`/`--pq-box`/Argon2id gated behind `make WITH_SDK=1`. Wire format stays v1.6 |
| v4.2.0 | Full (pure) post-quantum mode `--pq-only` (ML-KEM-768 only, envelope 0x06); critical fix for AES-CTR keystream reuse under `--dedup` (fresh random per-block nonce); clearer SDK keygen guidance. Wire format stays v1.6 |
| v4.2.1 | `vaptvupt info` now reports the real post-quantum mode (`--pq-only` no longer mislabelled as hybrid); reader-side only, no wire-format change |
| v5.0.0 | Genuine FIPS 203 ML-KEM-768 (validated vs OpenSSL); CLI data-loss/plaintext guards; AVX2 decoder OOB-read fix; GUI reworked for native PQ modes; cross-platform packaging. **Breaking:** `--pq`/`--pq-only` keys+archives from ≤4.2.1 do not decrypt |
| v5.1.0 | Codec 2.65.0; large compression-ratio gains (auto-`format_v2` + level-scaled block window — text extreme 3.77×→5.98×, logs 7.21×→9.07×); `--dedup` keeps a small block automatically; GUI compress-hang / job-completion-crash / Wayland-map fixes. Wire format stays v1.6, fully interoperable with 5.0.0 |

See [CHANGELOG.md](CHANGELOG.md) for detailed per-version changes.

---

## License

VaptVupt is dual-licensed:

- **AGPL-3.0-or-later** — most of the codebase (CLI, GUI, Jasmin source).
  See [`LICENSE`](LICENSE).
- **GPL-3.0-or-later** — the VaptVupt LZ codec only (`src/vv_*.c`,
  `src/vaptvupt_api.c` and headers), so it can be considered for
  upstreaming into the Linux/BSD kernels.
- **Commercial license** available for relief from AGPL/GPL terms. Contact
  `sac@securityops.co`.

Every source file carries an explicit SPDX header. See
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for full attribution.
VaptVupt contains no third-party source code.

## Acknowledgements

- **openSUSE packaging** — [Alessandro de Oliveira Faria (CABELO)](https://github.com/cabelo)
  &lt;cabelo@opensuse.org&gt;, openSUSE maintainer, packaged VaptVupt for the openSUSE
  Build Service (the recipe under [`packaging/opensuse/`](packaging/opensuse/)).

All compression and cryptography code is by Cristian Cezar Moisés.

## Related projects

All by Cristian Cezar Moisés, hosted on git.securityops.co:

- [vaptvupt](https://git.securityops.co/cristiancmoises/vaptvupt) — this repo (CLI + GUI)
- [zupt-android](https://git.securityops.co/cristiancmoises/zupt-android) — Android port
- [zupt-web](https://git.securityops.co/cristiancmoises/zupt-web) — Web frontend
- [libvuptsdk](https://git.securityops.co/cristiancmoises/libvuptsdk) — Standalone C SDK
- [vaptvupt-codec](https://git.securityops.co/cristiancmoises/vaptvupt-codec) — Standalone LZ + tANS codec

---
© 2026 Cristian Cezar Moisés — [git.securityops.co/cristiancmoises](https://git.securityops.co/cristiancmoises)
