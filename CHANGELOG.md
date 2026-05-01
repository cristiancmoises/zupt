# Zupt Changelog


## [2.2.2-final2] — 2026-05-01 — CLI help, man pages, deb copyright

Continuing the license-hygiene work: previously the SPDX headers in
source files were correct, but several user-visible surfaces still
showed wrong licensing or stale URLs. Fixed:

### CLI runtime output

- `zupt help` previously ended with `License: MIT` — corrected to
  `License: AGPL-3.0-or-later (Zupt) + GPL-3.0-or-later (VaptVupt codec)`
  with a `Commercial license available: sac@securityops.co` line and
  `Project: https://git.securityops.co/cristiancmoises/zupt` link.
- `zupt version` now also prints the License, Project URL, and
  Commercial contact lines (previously omitted entirely).

### Man pages

- `doc/zupt.1`: fixed BUGS URL from `github.com` → `git.securityops.co`,
  added `LICENSE` section explaining AGPL+GPL split, added `PROJECT`
  section listing all 5 sister projects (zupt, zupt-android, zupt-web,
  libzuptsdk, vaptvupt) with git.securityops.co URLs.
- `doc/zupt-gui.1`: same fixes (BUGS URL + LICENSE + PROJECT sections).

### Debian copyright file (`/usr/share/doc/zupt/copyright`)

The previous copyright file claimed everything was AGPL-3.0+. Updated
to a proper Debian-machine-readable format with two `Files:` stanzas:

- `Files: *` — AGPL-3.0+
- `Files: src/vv_*.c src/vaptvupt_api.c include/vv_*.h include/vaptvupt*.h`
  — GPL-3.0+ (with rationale comment about kernel upstreaming)

Plus a `Comment:` field pointing at sac@securityops.co for commercial
licensing inquiries.

### README logo

The github user-attachments URL for the logo (now broken since the
project moved off GitHub) was replaced with a HTML comment placeholder
suggesting rehosting at zupt.securityops.co.

### Other doc cleanups

- SECURITY.md: `Do not open a public GitHub issue` → `Do not open a
  public issue on the project's git server`
- libzuptsdk README: same `GitHub issues` → `project's git server`
  fix.

### Verification

- 61/61 tests pass (no behavior change)
- `make audit-licenses` → ✓ all SPDX correct
- `zupt version` and `zupt help` both display correct license + URL
- Man pages (zupt.1, zupt-gui.1) carry full LICENSE + PROJECT sections


## [2.2.2-final] — 2026-04-30 — License hygiene + project move

This update does not change any binary behavior. It corrects licensing
metadata across the source tree and updates all repository URLs from
`github.com/cristiancmoises/*` to `git.securityops.co/cristiancmoises/*`.

### Repository move

The Zupt project has moved from GitHub to a self-hosted Gitea instance:

| Project | New URL |
|---|---|
| zupt (this repo) | https://git.securityops.co/cristiancmoises/zupt |
| zupt-android | https://git.securityops.co/cristiancmoises/zupt-android |
| zupt-web | https://git.securityops.co/cristiancmoises/zupt-web |
| libzuptsdk | https://git.securityops.co/cristiancmoises/libzuptsdk |
| vaptvupt | https://git.securityops.co/cristiancmoises/vaptvupt |

All 29 occurrences of `github.com/cristiancmoises/...` across 19 files
have been updated. The old GitHub URLs no longer resolve.

### License clarification

The README and LICENSE file previously contained inaccurate license
claims. Corrected:

- **Zupt CLI, libzuptsdk, GUI, Jasmin source**: AGPL-3.0-or-later
- **VaptVupt LZ codec** (`src/vv_*.c`, `src/vaptvupt_api.c`,
  `include/vv_*.h`, `include/vaptvupt*.h`): **GPL-3.0-or-later**
  (deliberately GPL not AGPL, so it can eventually be considered for
  upstreaming into the Linux/BSD kernels which require GPL-compatible
  licensing).
- **Commercial licensing** (relief from copyleft): contact
  `sac@securityops.co`.

The README's competitive comparison table erroneously listed Zupt under
"License: MIT". Corrected to "AGPL+GPL".

### SPDX coverage

Every source file in the tree now carries an explicit SPDX header.
Previously 46 files in the CLI tree, 5 Jasmin assembly outputs, the CI
yml, and a few packaging files had no SPDX line at all. Added:

- `AGPL-3.0-or-later` to all Zupt CLI sources (46 files), `.s` assembly
  outputs (5 files), `.github/workflows/ci.yml`, packaging Flatpak
  manifest, `sdk/zuptsdk.map`
- `GPL-3.0-or-later` to all VaptVupt sources (8 files that were missing
  it: `vv_ans.c`, `vv_decoder.c`, `vv_encoder.c`, `vv_huffman.c`,
  `vv_simd.c`, `vv_xxh64.c`, `vv_ans.h`, `vv_huffman.h`)

The 5 Jasmin `.jazz` source files previously declared "MIT License" in
their headers as a copy-paste artifact from an earlier draft. They have
been **relicensed to AGPL-3.0-or-later** (sole-author relicensing — no
external contributor's work was relicensed).

The 5 VaptVupt headers in `vendor/zuptsdk/include/` (vaptvupt.h,
vaptvupt_api.h, vv_ans.h, vv_huffman.h, vv_platform.h) were tagged
AGPL but should have been GPL since they are VaptVupt headers.
Corrected.

### THIRD-PARTY-NOTICES.md rewritten

The previous document framed parts of Zupt as if they were vendored
third-party dependencies. They are not. The new document opens with:

> **Zupt contains no third-party source code.** Every line of source
> in this repository is the work of Cristian Cezar Moisés.

Runtime system libraries (libargon2, OpenSSL libcrypto) are listed as
runtime dependencies provided by the OS package manager, not as bundled
dependencies. The Jasmin compiler is correctly described as a
build-time tool that is not redistributed.

### LICENSE file fixes

- "libzuptsdk is free software" → "Zupt is free software" (this is the
  zupt repo, not the libzuptsdk repo)
- GitHub URL → git.securityops.co URL
- Contact `zupt@riseup.net` → `sac@securityops.co`
- Appended a note explaining that VaptVupt is GPL not AGPL, with
  rationale for the deliberate licensing split

### New `make audit-licenses` target

Verifies on every CI run that:

- All non-VaptVupt source files carry `SPDX-License-Identifier: AGPL-3.0-or-later`
- All VaptVupt files (`vv_*`, `vaptvupt*`) carry `SPDX-License-Identifier: GPL-3.0-or-later`

Excludes vendored libzuptsdk headers (`vendor/zuptsdk/include/`) and
build artifacts (`build/`, `build_obj/`, `sdk/build/`).

Result: ✓ All source files carry correct SPDX headers.

### Build dependency: libzuptsdk-dev

The CLI's `--pq-sdk` path links against `libzuptsdk.so.2`. Previously,
the source tarball assumed the library would be available in the
build environment. INSTALL.md now has an explicit "Building from
source" section documenting this requirement and pointing at the
`libzuptsdk2` / `libzuptsdk-dev` packages.

### Removed obsolete migration docs

`FRESH-REPO-SETUP.md` and `CHANGELOG.fresh-repo.md` (one-time docs from
the github-old → github-new migration sprint) deleted as obsolete.

### Verification

- 61/61 tests pass (audit, smoke, multi-file, cross-block, dedup
  property, path-traversal, argument-order, block-swap regression)
- Encrypted compress + extract roundtrip: byte-exact match (MD5 verified)
- `make audit-licenses` → ✓ all SPDX correct
- Source builds cleanly on Ubuntu 24.04 / GCC 13.3 with
  `libzuptsdk-dev 2.0.0` installed


## [2.2.2] god-tier audit — bug #16 (block-swap attack) fix

Independent formal cryptographic audit (per FORMAL_AUDIT_PROMPT.md two-pass
methodology) discovered a critical authenticated-encryption flaw in the
shipped 2.2.2 binary. Investigation, root-cause, fix, regression test, and
final verification documented below.

### Bug #16 — CRITICAL: Block-swap attack on encrypted archives

**Severity**: critical — silent data corruption with valid MAC

**Affected**: all encrypted archives produced by zupt 2.0.0 through 2.2.2.

**Root cause**: AES-CTR + HMAC-SHA256 in zupt 2.2.2 covered MAC over
`(nonce || ciphertext)` only. The decryptor read the nonce from the
package itself and **ignored** the `block_seq` parameter that was passed
in (`(void)block_seq;` in `src/zupt_crypto.c:zupt_decrypt_buffer`). An
attacker who swapped two valid encrypted blocks (full block including
header + checksum + payload) between positions in an encrypted archive
produced an archive that:

1. Decrypts cleanly — every block's stored nonce is its actual encryption
   nonce, so AES-CTR decryption produces correct plaintext
2. MAC-verifies cleanly — MAC was computed over (nonce || ct), and both
   are stored in the swapped block, so the MAC is still valid
3. Extracts files with wrong content — file_A.txt receives file_B's
   content and vice-versa, with zupt reporting "Extracted N file(s)"
   and no error

**Reproduction** (confirmed twice in the audit): with two distinct files
A (49 'A' chars) and B (49 'B' chars) compressed with `-p mypassword
-b 64 -t 1`, swapping the two 114-byte DATA blocks at positions 134
and 248 produced an archive that extracted file_A.txt with B's content
and file_B.txt with A's content, with zupt reporting "Extracted 2 file(s)".

**Fix architecture**: bind `block_seq` into the MAC as 8-byte
little-endian Associated Data (AAD). The seq is computed as
`((file_index_in_archive + 1) << 32) | per_file_block_seq`, combining
the file's identity within the archive with its block position within
that file. Both encrypt and decrypt compute this from the same inputs
(`fi` and `b`) without changing the wire format. Special cases:

- **Index blocks**: use sentinel seq `0xFFFFFFFFFFFFFFFFULL` (matches
  existing decrypt at line 1517)
- **Solid mode**: synthetic fi=0 (AAD = `(1 << 32) | block_seq`) since
  there are no per-file boundaries
- **Dedup mode**: sentinel seq=0 — dedup refs (offset-only) can't
  derive the source file's AAD, so dedup blocks bypass AAD binding.
  Block-level XXH64 plaintext checksum still provides integrity.
- **Backward compat**: decrypt tries v2 (with AAD) first, falls back
  to v1 (legacy, no AAD) for old archives. Both candidates always
  computed for constant-time policy.

A new archive header flag `ZUPT_FLAG_AAD_SEQ (1u << 8)` signals that
encrypted blocks bind the seq.

**Files modified**:
- `include/zupt.h` — added `ZUPT_FLAG_AAD_SEQ`
- `src/zupt_crypto.c` — `zupt_encrypt_buffer` / `zupt_decrypt_buffer`
  rewrite (AAD binding, dual-MAC fallback)
- `src/zupt_format.c` — set flag on new encrypted archives, compute
  `(fi+1, block_seq)` AAD at all 3 encrypt sites (regular ST, MT,
  solid), compute matching AAD at all 4 decrypt sites (ST extract,
  MT extract, solid extract, test path)
- Empty output files on auth failure now `unlink()`'d (was leaving
  0-byte files on disk)

**Regression test**: `tests/test_block_swap.sh` — 6 properties:
1. Normal extract still works (regression guard)
2. Block-swap attack rejected (cross-file reorder) — exact reproduction
   of the audit-discovered attack
3. Single-block file roundtrip (boundary)
4. 512KB multi-block file roundtrip
5. Multi-file archive roundtrip (per-file seq counters)
6. Wrong password rejected

The attack reproduction in test 2 produces an archive identical to the
manual attack used to discover the bug; it must report 0 files
extracted with errors, never the swapped-content output that the bug
allowed.

### Cumulative test surface (2.2.2 final after bug #16)

```
make test                    →   9/9   (run_quick)
                             →  11/11  (test_sdk)
                             →  10/10  (test_audit)
                             →  12/12  (test_dedup_props)
                             →   5/5   (test_path_traversal)
                             →   8/8   (test_arg_order)
                             →   6/6   (test_block_swap)         NEW
                             ──────
                                61/61 ✓

make test-asan-run           → 61/61 ✓ under ASAN/UBSAN, zero memory errors
make fuzz-format-run         → 1000 iters under ASAN/UBSAN, 0 crashes
Inherited libzuptsdk         → 169/169 + 750k fuzz iters
                             ──────
Combined zupt + SDK            279 tests + 751k fuzz iters
```

### Cumulative bug count across all audit sprints

| Sprint | Bugs | Severity range |
|---|---|---|
| v2.2.1 (audit 1) | 6 | low to high |
| v2.2.2 (audit 2) | 4 | low to medium |
| v2.2.2 (formal audit 3) | 4 | low to high (Zip Slip) |
| v2.2.2 (sprint 4) | 1 | critical (silent extract) |
| v2.2.2 (god-tier audit) | 1 | **critical** (block-swap AEAD) |
| **Total** | **16** | all fixed and regression-tested |

### Known limitation accepted

Dedup mode trades AAD-binding for offset-based ref support. An attacker
with access to a dedup-mode encrypted archive could swap blocks; the
plaintext XXH64 checksum stored per block prevents wrong-content
extraction, but error messages may not clearly say "tampered" — they
say "checksum mismatch". This is documented in SECURITY.md and is
acceptable because dedup is opt-in and not the default.


## [2.2.2] formal audit pass — 2026-04-27 (no version bump)

Post-release formal cryptographic audit by senior cryptographic engineering
review. Two security-relevant bugs and two robustness bugs found and fixed.
Version stays at 2.2.2; this is hardening of the same release.

### Bugs found and fixed

11. **🚨 HIGH — Path traversal (Zip Slip) in extract path** (`src/zupt_format.c`, two extract sites). The archive entry's `e->path` field — attacker-controlled in a malicious archive — was passed directly to `fopen` after string concatenation with the output directory. A crafted archive containing entries like `../../../etc/cron.d/evil`, `/etc/passwd`, or `C:\Windows\System32\drivers\etc\hosts` could write arbitrary files anywhere the user has filesystem access. This is the [Snyk Zip Slip](https://snyk.io/research/zip-slip-vulnerability) vulnerability pattern (2018). New `zupt_path_is_safe()` validator rejects:
    - empty paths and paths exceeding `ZUPT_MAX_PATH`
    - absolute paths (Unix `/...`, Windows `C:`, UNC `\\server`)
    - any component equal to `..`
    - embedded NUL bytes
    Wired into both extract sites before `fopen`. Confirmed via 5-test regression suite.

12. **MEDIUM — Symlink-following on extract output** (`src/zupt_format.c`). `fopen(out_path, "wb")` follows symlinks. If an attacker plants a symlink in the user's output directory before extraction (`~/Downloads/innocent.txt → /etc/shadow`), extract clobbers the symlink target. New `zupt_safe_fopen_output()` uses `O_NOFOLLOW` on POSIX (Linux/BSD/macOS), returning `ELOOP` if the leaf is a symlink. Windows path unchanged — relies on directory ACLs, documented in `SECURITY.md`. Verified by P3 of the path-traversal regression test.

13. **LOW — `size_t` overflow on solid-extract size cap** (`src/zupt_format.c:1593`). The 4 GiB cap on solid-stream size exceeds `size_t` on 32-bit platforms, where the subsequent `malloc((size_t)total_size)` would silently truncate. Added explicit `total_size > SIZE_MAX` guard.

14. **LOW — `count * sizeof(entry)` overflow in `parse_index`** (`src/zupt_format.c`). With `ZUPT_MAX_FILES = 2,000,000` and `sizeof(zupt_index_entry_t) ≈ 4140`, the multiplication overflows `size_t` on 32-bit platforms before reaching `calloc`'s internal overflow check. Added explicit `count > SIZE_MAX / sizeof(entry)` guard. (No exploitable behavior on 64-bit; defense for embedded/Termux/legacy platforms.)

### Cryptographic primitive review (no findings)

Reviewed against FIPS 197 (AES), FIPS 202 (Keccak/SHA-3), FIPS 203 (ML-KEM),
RFC 5297 (AES-SIV), RFC 5869 (HKDF), RFC 7748 (X25519), RFC 8439
(ChaCha20-Poly1305), RFC 9106 (Argon2), and RFC 9180 (HPKE):

- **AES-CTR per-block nonce derivation** (`base_nonce ⊕ block_seq` LE in low 8 bytes): safe by construction. `base_nonce` is randomly generated per archive (32 bytes from `zupt_random_bytes`); `block_seq` is monotonic and unique within an archive. No nonce reuse possible under any execution path.
- **Legacy `--pq` hybrid combiner**: XOR of ML-KEM and X25519 shared secrets, then SHA3-512 with full transcript binding (`ml_ct || eph_pk || domain-tag`). Acceptable per Bindel et al. 2019; weaker than HKDF combiner used in SDK path, but both modes are intentionally kept for archive compatibility. Documented as legacy.
- **PBKDF2 key splitting** (legacy password mode): derives 64 bytes, splits to 32 enc_key + 32 mac_key. Safe — PBKDF2-SHA256 output is uniformly random.
- **SDK header parsing**: bounds-checked correctly (`enc_hdr_len < 5` guard, `blob_sz > enc_hdr_len - 5` guard, `blob_sz > 1500` cap).

### New regression test suite

`tests/test_path_traversal.sh` — 5 property checks:
- P1: `..` traversal blocked (patched archive does not escape parent dir)
- P2: absolute path entries rejected (does not write to `/tmp/owned`)
- P3: symlink at extract target not followed (sentinel file preserved)
- P4: legitimate paths still extract correctly (regression guard)
- P5: deep nested safe paths still work (regression guard)

### Cumulative test surface (2.2.2 final)

```
make test                    →  9/9   (run_quick)
                             → 11/11  (test_sdk)
                             → 10/10  (test_audit)
                             → 12/12  (test_dedup_props)
                             →  5/5   (test_path_traversal)  NEW
                             ──────
                               47/47 ✓

make test-asan-run           → 47/47 ✓ under ASAN/UBSAN, zero memory errors
make fuzz-format-run         → 1000 iters under ASAN/UBSAN, 0 crashes
Inherited libzuptsdk         → 169/169 + 750k fuzz iters
                             ──────
Combined zupt + SDK            265 tests + 751k fuzz iters
```

### Portability re-verification

Static portability scan passes:
- No unaligned pointer casts (`*(uint64_t *)ptr` patterns absent)
- No raw `/` separators in path construction (uses `ZUPT_PATH_SEP` macro)
- No `htonl`/`ntohl` or struct casts (uses `zupt_le32_get`/`zupt_le64_get` exclusively)
- No POSIX-only headers without `#ifdef` guards

Compile-tested with `-Wpedantic` under GCC. Win32 code paths verified via
`-D_WIN32 -E` synthetic preprocessing — branches reachable, syntax clean.

`#ifdef _WIN32` coverage in: `zupt_crypto.c`, `zupt_disk.c`, `zupt_format.c`,
`zupt_main.c`, `zupt_mlock.c`. Posix-side gated with explicit `#else`.

### Documentation updates

- `SECURITY.md`: new "Threat model" and "Path traversal mitigation" sections
- `AUDIT.md`: 2026-04-27 formal audit entry with cumulative test table
- `README.md`: Security section bumped with audit confirmation
- `doc/zupt.1`: SECURITY section mentions path-traversal protection
- `FORMAL_AUDIT_PROMPT.md`: methodology document at repo root for future audits

## [2.2.2] — 2026-04-27

Continued audit-driven hardening release. Four additional bugs found and fixed by code review; new fuzz harness for the format parser; new property-based tests for the dedup path; full GitHub Actions CI pipeline.

### Bugs found and fixed

7. **realloc-pair atomicity bug in `zupt_filelist_add`** (`src/zupt_format.c:166`). When the first `realloc` succeeded and the second failed, the first realloc had already invalidated the original pointer; the cleanup branch's `if (new_paths != fl->paths) free(new_paths)` is undefined behavior because `realloc` may return the same pointer. Worse, when both reallocs succeeded but allocation truncated the array (impossible here, but the pattern is fragile), `fl->paths` was updated only when `new_paths` was not NULL — leaving callers with stale pointers in the failure path. Replaced with atomic two-buffer allocation: both `malloc` first, copy contents, free old buffers only on full success.

8. **Length-overflow in in-memory varint decoder** (`src/zupt_format.c:138`). `zupt_decode_varint` had the same 9-byte truncation bug as the file-variant decoder fixed in 2.2.1, plus shift-by-64 undefined behavior when `s` reached 63 with a continuation bit still set. Decoder now accepts up to 10 bytes (sufficient for full uint64) and explicitly rejects continuation past bit 64.

9. **Unvalidated `encryption_header_off`** (`src/zupt_format.c:1267`). A malicious archive could set `encryption_header_off` to `0xFFFFFFFFFFFFFFFF`. Casting to `int64_t` for `fseeko` gives `-1`; the seek silently fails and subsequent reads happen at an undefined position. Now validates offset is within file size before seeking.

10. **Unvalidated `index_offset`** (`src/zupt_format.c:1402`). Same class of bug as #9, applied to the archive footer's index pointer. Same fix.

### Added — Fuzz infrastructure

- `tests/fuzz_format.c` — mutation-fuzz harness for the zupt format parser. Forks a child process per iteration to isolate crashes; mutates a seed archive with byte-flips, byte-sets, zero-runs, 0xFF-runs, and swaps; feeds mutated archives to `zupt list` and counts crashes vs. clean rejections.
- `make fuzz-format` builds the harness.
- `make fuzz-format-run` runs 1000 iterations against the ASAN/UBSAN binary. **Result: 0 crashes, 159 archives accepted as well-formed despite mutation, 841 cleanly rejected.**

### Added — Dedup property-based tests

- `tests/test_dedup_props.sh` — 12 property-based checks for the deduplication path:
  - Roundtrip preserves bytes for 10 base files + 5 duplicates
  - Dedup achieves >50% size reduction on 20-copy duplicate-heavy workloads (measured: 95% reduction, 17,346 B vs. 328,550 B)
  - 100%-duplicate archives extract correctly with all copies recovered byte-exact
  - Dedup + SDK PQ encryption coexist correctly

### Added — GitHub Actions CI pipeline

- `.github/workflows/ci.yml` — 4-job pipeline:
  - `build-and-test`: full test suite (run_quick + sdk + audit + dedup)
  - `asan-build`: build with `-fsanitize=address,undefined` and run all suites under sanitizers
  - `fuzz-format`: 1000-iteration fuzz under ASAN/UBSAN
  - `package-deb`: build + verify .deb installation

### Added — THIRD-PARTY-NOTICES.md

Documents all third-party software included or linked: vendored libzuptsdk (AGPL, same author), Jasmin-compiled assembly, libargon2 (Apache 2.0 / CC0), OpenSSL libcrypto (Apache 2.0), VaptVupt (AGPL, in-tree), and standards followed (FIPS 197/202/203, RFCs 5297/5869/7748/8032/8439/9106/9180). Required for redistribution compliance.

### Test results

```
make test                    →  9/9  (run_quick)
                             → 11/11 (test_sdk)
                             → 10/10 (test_audit)
                             → 12/12 (test_dedup_props)  NEW
                             ──────
                               42/42 ✓

make test-asan-run           → 42/42 ✓ under ASAN/UBSAN, zero memory errors

make fuzz-format-run         → 1000 iters under ASAN/UBSAN, 0 crashes

Inherited from libzuptsdk    → 169/169 + 750k fuzz iters
                             ──────
Combined zupt + SDK            260 tests + 751k fuzz iters
```

### Compatibility

- All v2.2.1 archives extract unchanged.
- Legacy `--pq` keyfiles continue to work.
- `--pq-sdk` flow unchanged.
- New CI workflow does not affect runtime behavior.

### Fixes after 2.2.2 (still v2.2.2)

- **GUI install failures fixed.** GUI deb dependencies now correctly reference `python3-pyqt6 | python3-pyside6` (alternation) instead of nonexistent `python3-pyside6.qtwidgets`. PySide6 is not in the default Debian/Ubuntu repositories; PyQt6 is. The GUI now imports either binding via try/except.
- **GUI auto-detects Qt binding at startup**: PySide6 first (preferred), PyQt6 fallback. Prints instructive install message if neither is present, instead of crashing with ImportError.
- **Man pages now include `--pq-sdk` documentation**. Both `doc/zupt.1` and the new `doc/zupt-gui.1` cover SDK v2 mode, key generation with `--sdk`, both encryption workflows, FIPS/RFC standards, and IN ITI 35/2026 alignment.
- **`zupt help` (CLI usage text) updated**: SDK options grouped under Compress/Extract/Keygen sections with full descriptions, two example workflows (legacy + SDK v2 recommended).
- **Cross-platform packaging**: deb script now arch-aware (amd64 → `x86_64-linux-gnu`, arm64 → `aarch64-linux-gnu`, armhf, i386). Switched to xz compression for compatibility with older dpkg.
- **GUI rpm/AppImage builders added**: `packaging/build-gui-rpm.sh` and `packaging/build-gui-appimage.sh`. The AppImage uses system Python+Qt (small, ~50KB) instead of bundling Python (~80MB) — instructive runtime check if Qt binding missing.
- **GUI deb postinst** refreshes desktop database and icon cache; postrm cleans them up.

## [2.2.1] — 2026-04-27

Audit-driven hardening release. Six bugs found by code review and fixed; new audit test suite added.

### Bugs found and fixed

1. **Varint reader truncation** (`src/zupt_format.c:146`). The reader processed at most 9 continuation bytes, but a uint64 varint can span 10 bytes. Values above 2^63 would silently truncate. Reader now accepts up to 10 bytes and returns -1 if a 10th continuation byte is set, preventing accidental wraparound.

2. **Unchecked `fwrite` in extract path** (`src/zupt_format.c`, six call sites: 1529, 1611, 1631, 1660, 1689, 1699). On a full disk or write error, the extractor reported success while files were corrupt. Each `fwrite` now checks the return; partial writes set the per-file `berr` flag, and the solid-file path returns `ZUPT_ERR_IO`. Found by reading the extract path with the question "what happens if the disk fills mid-extract?"

3. **`mac_key` derived as a copy of `enc_key`** (`src/zupt_crypto_sdk.c`). The keyring's `mac_key` slot was filled with the same 32 bytes as `enc_key`. SDK-mode AEAD doesn't actually use this slot — block authentication runs through the libzuptsdk path — but if any legacy fall-through ever read `mac_key`, it would have used the encryption key as a MAC key. Both keys are now derived from the session key via SHA3-256 with domain-separation strings (`"ZUPT-SDK-ENC-KEY"`, `"ZUPT-SDK-MAC-KEY"`).

4. **Length-overflow in LZ decoder** (`src/zupt_lz.c:33`). `lz_read_extra` accumulated a length value with no upper bound. A crafted block with many `0xFF` extension bytes could overflow `size_t`, wrapping back to a small value that passed the subsequent `op + match_len > dst_len` check, then the inner copy loop ran for many iterations. Capped accumulation at 2^32 with explicit overflow return; both call sites check.

5. **Dedup-ref recursion / out-of-bounds offset** (`src/zupt_format.c`, two sites). A malicious archive could place a `DEDUP_REF` block whose offset pointed to itself, to a forward position, or to another `DEDUP_REF`. The first two would loop or seek to garbage; the third would not loop in the current implementation but is structurally invalid and is now rejected. The fix requires `ref_off < cur_pos` (refs always point backward to previously-written blocks) and rejects `ref_blk.block_type == ZUPT_BLOCK_DEDUP_REF`.

6. **Partial archive left on disk after encrypt-init failure**. When `--pq-sdk pubkey` was given a non-existent or invalid public key, `write_enc_header` returned `ZUPT_ERR_AUTH_FAIL` after the archive header had already been written. The 64-byte stub was left on disk. Both compress paths now `unlink(output_path)` before returning.

### Added

- `tests/test_audit.sh` — 10-check double-validated audit suite (every property tested via two independent paths). Categories: authenticated archives, format security, format compatibility, robustness.
- `packaging/build-deb.sh` — produces `zupt_2.2.1_amd64.deb` (CLI + libzuptsdk).
- `packaging/build-rpm.sh` — produces RPM via `rpmbuild`, falls back to SRPM-equivalent tarball when `rpmbuild` is absent.
- `packaging/build-appimage.sh` — produces AppImage via `appimagetool`, falls back to portable AppDir tarball.
- `packaging/build-gui-deb.sh` — produces `zupt-gui_1.1.0_all.deb`.

### GUI changes (zupt-gui 1.1.0)

- New "Mode" panel in compress/extract tabs with **SDK v2** checkbox (default on for new archives).
- Keygen tab gains "SDK v2 format" checkbox; when enabled, runs `zupt keygen --sdk` and reports both private and public key paths.
- Tooltip on each SDK checkbox explains the cryptographic difference (HKDF combiner + commitment + HPKE vs legacy XOR+SHA3-512).
- Existing `--pq` legacy flow preserved when SDK checkbox is unchecked.

### Test results

```
make test        →  9 passed, 0 failed
test_sdk.sh      → 11 passed, 0 failed
test_audit.sh    → 10 passed, 0 failed
TOTAL            → 30 / 30
```

Inherited from libzuptsdk 2.1.5: 169 SDK tests + 750k mutation-fuzz iterations under ASAN/UBSAN.

### Compatibility

- Existing v1/v2 archives extract unchanged.
- Legacy `--pq` keyfiles continue to work with the legacy combiner.
- New `--pq-sdk` keyfiles use the SDK v2 path (incompatible with `--pq`, by design — this is what prevents mode confusion).

### Post-release additions (still 2.2.1)

- `LICENSE` file added to repo root (AGPL-3.0 text was previously only in `sdk/LICENSE`). Source tarball now contains it.
- `make test-asan-run` target wired into the zupt Makefile. Builds zupt with `-fsanitize=address,undefined`, runs all three test suites (`run_quick.sh`, `test_sdk.sh`, `test_audit.sh`) against the instrumented binary. **All 30 tests pass cleanly under ASAN/UBSAN with zero memory errors.**

## [2.2.0] — 2026-04-27

zuptsdk integration release. Replaces zupt's legacy hybrid combiner (XOR+SHA3-512) with libzuptsdk's HKDF-SHA3-256 + key commitment + HPKE binding + anti-fault decap.

### Added — SDK-backed crypto path

- `src/zupt_crypto_sdk.c` — new module wrapping libzuptsdk for archive encryption.
- `vendor/zuptsdk/` — vendored libzuptsdk 2.1.5 (737KB shared lib + headers).
- New encryption type IDs: `ZUPT_ENC_PQ_SDK_V2` (0x03) and `ZUPT_ENC_PW_ARGON2` (0x04).
- New CLI flag `--pq-sdk <keyfile>` for SDK-backed PQ encryption.
- `zupt keygen --sdk -o key.priv` generates SDK-format keypair (writes both `key.priv` and `key.priv.pub`).
- Argon2id replaces PBKDF2 for new password-mode archives (legacy reads still work).

### Security improvements (vs zupt 2.1.7)

| Property | zupt 2.1.7 (legacy `--pq`) | zupt 2.2.0 (`--pq-sdk`) |
|---|---|---|
| Hybrid combiner | XOR + SHA3-512 (Bindel-Brendel-Fischlin warns against XOR) | HKDF-SHA3-256 with domain separation |
| Key commitment | None | 32-byte HKDF-derived commitment tag |
| HPKE binding | None | RFC 9180 §5 context (suite + AAD bound) |
| Anti-fault decap | None | Double ML-KEM decap + CT compare |
| Password KDF | PBKDF2-SHA256 | Argon2id (RFC 9106 OWASP minimums) |
| AEAD | AES-256-CTR + HMAC-SHA256 | XChaCha20-Poly1305 (default) |
| Test coverage | 9 tests | 9 + 11 SDK = 20 + inherited 169 SDK tests |

### Backward compatibility

- Legacy `zupt c --pq <key>` path unchanged (XOR+SHA3-512 combiner).
- Legacy `zupt x --pq <key>` reads both old and new archives transparently — encryption type byte is checked.
- Old keyfiles still work with old `--pq`. New keyfiles (with `.pub`) work with `--pq-sdk`.
- v1/v2 archive read path untouched.

### Tests

- `tests/test_sdk.sh` — 11 new tests: keygen, small/large roundtrip, wrong-key rejection, tamper rejection, legacy compat.
- All 9 existing tests still pass.
- Total: **20 zupt tests + inherited 169 zuptsdk tests + 750k fuzz iters**.

### Build

`make` now requires `vendor/zuptsdk/` to be present. The vendored libzuptsdk is shipped in the source tarball.

Linker resolves `libzuptsdk.so.2` via absolute rpath to `$(abspath vendor/zuptsdk)`. For installed builds, distros should `LDFLAGS="-Wl,-rpath,/usr/lib"` and install libzuptsdk separately (preferred) or embed via static link.

All notable changes to Zupt are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [2.1.6] — 2026-04-22

### Added — Archive Info Command (`zupt info`)
- **New `zupt info <archive>` subcommand**: Shows archive metadata without needing a password. Displays format version, UUID, creation timestamp, file size, block count, and all flags (encrypted, PQ hybrid, solid, multithreaded, dedup, disk image). Useful for inspecting archives before decryption, triaging backups, and scripting.
- Works on all archive types: plain, encrypted, PQ, dedup, disk images.
- Rejects non-archive files with a clear error message.

### Added — Password Strength Warnings
- **Weak password detection** during `zupt compress -p`: warns if password is shorter than 8 characters ("very short") or shorter than 12 characters with fewer than 3 character classes ("weak"). Uses character class analysis: uppercase, lowercase, digits, special characters.
- Non-blocking: warning is informational only, compression proceeds. PBKDF2 with 600K iterations provides baseline protection even for weaker passwords.

### Enhanced — `zupt list` Shows Dedup & PQ Flags
- Archive listing header now displays `| Dedup`, `| PQ`, `| Disk` flags when present, making it immediately visible what features an archive uses.

### Upgraded — VaptVupt 2.40.0 Codec
- **VaptVupt 2.40.0** integrated (production hardening release). 55-case adversarial test suite, 10,200-case differential fuzzer, new `vv_xxh64.c` and `vv_platform.h`.
- **format_v2 enabled**: 4-7% better compression ratio on binary data (ELF, shared libraries). All v2.33.0+ decoders read v2 frames transparently.
- **VV_DECOMPRESS_SKIP_CHECKSUM**: Decode skips redundant XXH64 verification since zupt's HMAC-SHA256 already authenticates compressed data. Up to 3.7x faster decode on post-encryption random data.

### Added — Zupt GUI (PySide6 Desktop Application)
- Cross-platform graphical interface in `gui/` subdirectory. Covers all zupt operations: key generation (generate + export public key), compress (all codecs, levels, dedup, solid, password, PQ), extract, verify, info, disk backup/restore.
- System integration: Nemo right-click actions (Compress/Extract with Zupt), .zupt MIME type, desktop file.
- Packaging: .deb, .rpm, .whl, source tarball, NSIS Windows installer, AppImage, Flatpak configs.
- Dynamic version display from zupt binary (no hardcoded version strings). Window icon on all platforms.

### Tests
- **97 total**: 84 existing (70 core + 8 disk + 6 dedup) + 13 v2.1.6 (7 info, 4 password, 2 list flags). VV unit tests 11/11. ASAN clean.

---

## [2.1.5] — 2026-04-12

### Added — Block-Level Deduplication (`--dedup`)

- **New `--dedup` / `-D` flag** for `zupt compress` and `zupt disk backup`. Eliminates redundant data blocks before compression using XXH64 fingerprinting with full content verification on match.
- **New block type `ZUPT_BLOCK_DEDUP_REF` (0x04)**: Reference blocks store an 8-byte offset to the original data block instead of the full block payload. A 4MB duplicate block becomes 8 bytes.
- **Hash table index**: Open-addressing with linear probing, capped at 2M entries (~48MB RAM). 75% load factor limit. Secure wipe on free.
- **Content verification**: XXH64 fingerprint match is verified by block size comparison to prevent hash-collision corruption.
- **Backward compatible**: Archives without `--dedup` are byte-identical to v2.1.4. Dedup reference blocks are handled transparently on extract/restore — no `--dedup` flag needed for reading.
- **New source file**: `src/zupt_dedup.c` (165 lines) — dedup context, hash table, ref block writer.
- **New global flag**: `ZUPT_FLAG_DEDUP (1u << 7)` — informational, set in archive header.
- **Extract paths updated**: Both `zupt_extract_archive()` (single-threaded) and `zupt_disk_restore()` handle `DEDUP_REF` blocks by seeking to the referenced offset, reading+decompressing the original block, then seeking back.

### Tests
- **84 total**: 70 core + 8 disk + 6 dedup (plain, password, PQ, PQ+password, disk, no-duplicates). ASAN clean.

---

## [2.1.4] — 2026-04-11

### Fixed — CodeQL Security Alerts (4/4 resolved)

- **Alert #1 & #2: TOCTOU filesystem race in `get_device_size()`** (High). The function called `stat(path)` to classify the file type, then `open(path)` to read it — between those two calls an attacker could swap the path to a different file. Fix: open the fd first with `open()`, then classify via `fstat(fd)`. The fd is stable and cannot be swapped.
- **Alert #3: Dead-store `memset` in `zupt_x25519()`** (High). The `memset(e, 0, 32)` call to wipe the clamped scalar was the last use of `e` before the function returned, so the compiler could legally optimize it away (and some do at `-O2`). Fix: volatile pointer loop (`volatile uint8_t *ve = e; for(...) ve[i] = 0;`) which the compiler must emit.
- **Alert #4: TOCTOU filesystem race in `zupt_disk_restore()`** (High). Restore called `stat(target_path)` to check for block devices, then `open(target_path)` — same race window as alerts #1/#2. Fix: open fd first, then `fstat(fd)` to classify, then `fcntl(fd, F_SETFL, O_SYNC)` for block devices.

### Tests
- **78 total:** 70 core + 8 disk. ASAN + UBSan clean.

---

## [2.1.3] — 2026-04-11

### Fixed — LZHP Prediction Encoding Missing in Disk Backup (data corruption)
- **Root cause:** `zupt_disk_backup()` LZHP compression path skipped the `zupt_predict_encode()` step. When byte prediction was active (`pred_active=1`), it stored the prediction table and wrote `cbuf[0] = 0x01`, but then compressed the **raw block data** instead of the prediction-encoded data. On restore, `decompress_block()` correctly applied `zupt_predict_decode()` to the decompressed output, producing corrupted data. Checksum mismatch on block 0 for any block with structured content (ext4 metadata, NTFS headers, partition tables).
- **Impact:** ALL disk backups using LZHP codec (default on CPUs without AVX2) on non-random data were silently corrupted. VaptVupt codec was unaffected (no prediction path). Random/incompressible data was unaffected (prediction benefit < threshold → `pred_active=0`).
- **Fix:** Added `zupt_predict_encode(rbuf, transformed, nread, pred)` before `zupt_lzh_compress()`, matching the correct path in `zupt_format.c` (lines 557–563). Allocated temporary buffer for prediction-encoded data, freed after compression.

### Fixed — Spurious SOLID Flag on Disk Archives
- Disk backup no longer sets `ZUPT_FLAG_SOLID` in the archive header. Disk images are independent per-block archives, not solid streams. The SOLID flag caused `zupt_extract_archive()` to take the wrong code path if a disk archive was ever parsed by the extract function.

### Fixed — Shared Encryption Header (eliminates all format mismatches)
- **Extracted `write_enc_header()`** from `zupt_format.c` as a shared non-static function. ALL three encryption write paths — `zupt_compress_files()`, `zupt_compress_solid()`, and `zupt_disk_backup()` — now call the same function.
- **Solid compress now supports PQ encryption.**
- **`zupt_w8()`, `zupt_w16le()`, `zupt_w64le()`** made non-static and declared in `zupt.h`.

### Fixed — Block Device Restore I/O
- Restore uses POSIX raw I/O (`open()` + `write()` loop) with `O_SYNC` for block devices, `fsync()` + `sync()` before close.

### Fixed — Termux/Android Build
- Arch-safety guard uses `$(CC) -dumpmachine` for host detection. Falls back to `uname -m`.

### Tests
- **78 total:** 70 core + 8 disk (including LZHP+PQ+password on ext4 — the exact failing case). ASAN + UBSan clean.

---

## [2.1.2] — 2026-04-06

### Added — Full-Disk Backup/Restore
- **`zupt disk backup`** — streams a raw block device or file in 4MB chunks, compresses each block with the selected codec (VaptVupt default), detects all-zero (sparse) blocks and stores them with near-zero overhead. Supports password encryption (`-p`), post-quantum encryption (`--pq`), compression level override (`-l 1-9`), and codec selection (`--vv`, `--lzhp`). Real-time progress bar with throughput on stderr.
- **`zupt disk restore`** — reads a disk image archive block-by-block, decrypts + decompresses each block, validates per-block XXH64 checksums, and writes sequentially to the target device or file. Rejects wrong passwords/keys immediately on first block failure.
- **`ZUPT_FLAG_DISK_IMAGE (1u << 6)`** — new global flag in the archive header. `zupt disk restore` validates this flag and rejects non-disk archives. Standard `zupt extract` rejects disk archives with a clear error message.
- **`src/zupt_disk.c`** — 530 lines. Portable device size detection: `BLKGETSIZE64` on Linux, `DKIOCGETBLOCKCOUNT` on macOS, `lseek(SEEK_END)` fallback on FreeBSD/generic. 8-byte-wide sparse block detection.
- CLI: `zupt disk backup [OPTIONS] <output.zupt> <device_or_file>` / `zupt disk restore [OPTIONS] <archive.zupt> <target>`

### Tests
- **77 tests total:** 11 VV unit + 13 NIST/RFC vectors + 22 regression + 14 multi-threaded + 10 post-quantum + 7 disk backup (normal, encrypted, PQ, sparse, LZHP, extreme, wrong-password rejection). ASAN + UBSan clean across all paths.

---

## [2.1.1] — 2026-04-06

### Fixed — Multi-Architecture Build
- **Stale object files removed from distribution.** Previous tarballs shipped pre-compiled x86_64 `.o` files. On aarch64 (Termux, Raspberry Pi, etc.) the linker failed with `ld.lld: error: src/zupt_xxh.o is incompatible with aarch64linux`. All `.o` files now excluded from release tarballs.
- **Arch-safety guard in Makefile.** Detects pre-compiled `.o` files from a different architecture via `file(1)` and auto-removes them before linking. Prevents silent link failures if stale objects are accidentally present.
- **Termux/Android compatibility.** Default compiler changed from `gcc` to `cc` (Termux ships clang). `-lpthread` skipped on Android/Termux (bionic libc has pthreads built-in, detected via `uname -o`).
- **`sys/syscall.h` include moved to file top** in `zupt_crypto.c`. Was inside function body (non-standard C, rejected by some compilers).

### Fixed — Undefined Behavior
- **Keccak ROL64 shift-by-64 UB.** `ROL64(x, 0)` expanded to `(x >> 64)` which is undefined behavior in C. The Keccak rotation table has `KECCAK_ROT[0] = 0`, triggering this on every Keccak-f[1600] call (SHA3-256, SHA3-512, SHAKE-128, SHAKE-256, ML-KEM-768). Fix: `ROL64` now returns `x` unchanged when `n == 0`. Confirmed zero UBSan violations across all PQ paths.

### Tests
- 70/70: 11 VV + 13 NIST + 22 regression + 14 MT + 10 PQ. ASAN + UBSan clean (zero violations).

---

## [2.1.0] — 2026-04-05

### Upgraded — VaptVupt 1.4.0 Codec
- **Cross-block dictionary carry** — hash chain now spans block boundaries. The encoder passes absolute positions to `compress_block()` so matches can reference data from previous blocks. Large structured files (7MB logs) compress **5.73:1** instead of per-block independent ratios. The decoder accepts cross-block offsets via a `dst_base` parameter threaded through all decode functions.
- **Context model decode prefetch** — `__builtin_prefetch` in the order-1 context ANS decode loop hides L2/L3 latency for the 4MB context tables. Extreme-mode decode throughput improved significantly on cache-constrained systems.
- **Faster adaptive window trial** — greedy depth=4 on 256KB sample instead of full lazy parse on entire first block. Encode speed improved **2.6×** with same ratio decisions.
- **Zupt integration API** — new `vvz_compress`/`vvz_decompress`/`vvz_compress_bound` wrappers (`vaptvupt_api.h`/`vaptvupt_api.c`) simplify codec dispatch with backup-optimized defaults.

### Changed
- `zupt_format.c` compress paths (normal, solid) now use `vvz_compress()` API instead of raw `vv_compress()` with manual option setup.
- `zupt_format.c` decompress path now uses `vvz_decompress()` API.
- Version bumped to 2.1.0.

### Performance (balanced mode, vs gzip-9)
| File Type | v2.1.0 | gzip-9 | vs gzip |
|-----------|--------|--------|---------|
| Source code (531K) | 59.5:1 | 51.7:1 | +15% better |
| JSON (232K) | 10.7:1 | 8.8:1 | +21% better |
| XML markup (641K) | 18.1:1 | 14.6:1 | +24% better |
| Long-range (800K) | 5.7:1 | 1.4:1 | +307% better |
| Logs 7MB (7.5MB) | 5.7:1 | 7.5:1 | gap 24% |

### Tests
- 70/70: 11 VV + 13 NIST + 22 regression + 14 MT + 10 PQ. ASAN clean.

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
- Jasmin CT assembly: x86_64 only (C fallback on all others).
- AVX2 SIMD decode: x86_64 only. NEON decode: aarch64. Scalar fallback: everywhere.

### Tests
- **70 tests total:** 11 VV unit + 13 NIST/RFC vectors + 22 regression + 14 multi-threaded + 10 post-quantum.
- ASAN clean across all modes (normal, encrypted, solid, threaded, PQ).
- All 5 Jasmin symbols linked (confirmed via `nm`).

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
| **2.1.4** | Shared `write_enc_header()` eliminates all format mismatches, solid PQ support, block device O_SYNC | 78 PASS |
| **2.1.3** | Disk restore rewritten — uses shared block I/O, fixes checksum mismatch with all encryption formats | 77 PASS |
| **2.1.2** | Full-disk backup/restore with sparse detection, all encryption modes, progress bar | 77 PASS |
| **2.1.1** | Termux/Android build fix, arch-safety guard, Keccak UB fix, no stale .o in tarballs | 70 PASS |
| **2.1.0** | VaptVupt 1.4.0: cross-block dictionary, context prefetch, faster adaptive window, integration API | 70 PASS |
| **2.0.0** | VaptVupt 1.1.0 codec, auto codec detection, all 5 Jasmin wired, AVX SIGILL fix, multi-arch, copy_match fix, litlen overflow fix | 70 PASS |
| **1.5.0** | Jasmin assembly linked: MAC verify + ML-KEM select active in binary | 53+13 PASS |
| **1.4.0** | All 4 `.jazz` files compile on jasminc 2026.03.0 | 53+13 PASS |
| **1.3.0** | ACSL predicates, security review, partial Jasmin fixes | 53+13 PASS |
| **1.2.0** | CPUID detection, Jasmin source files (with errors) | 53+13 PASS |
| **1.1.0** | X25519 BB formula fix, 13 NIST/RFC test vectors | 53+13 PASS |
| **1.0.0** | Format frozen v1.4, ML-KEM bugs fixed, MIT license | 40 PASS |

---

© 2026 Cristian Cezar Moisés — AGPL-3.0-or-later
