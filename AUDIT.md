# Security Audit — VaptVupt v4.0.0

**Date:** 2026-05-20
**Author:** Cristian Cezar Moisés
**Audit type:** Self-audit with formal verification (Jasmin CT proofs, ACSL contracts) and NIST/RFC test vectors
**Status:** No independent third-party audit performed

History:
- v2.0.0 — 2026-03-29 — initial audit baseline.
- v2.2.4 — 2026-05-19 — five findings (F-01..F-05) closed.
- v2.2.5 — 2026-05-19 — F-06 (high) and F-07 closed.
- v2.3.0 — 2026-05-20 — F-08 closed via AIT (format v1.4 → v1.5).
- v2.3.1 — 2026-05-20 — F-09 closed via preface-AAD MAC (format v1.5 → v1.6).
  Exhaustive byte sweep on PQ-SDK archive: **0/1827 undetected**.
- v2.4.0 — 2026-05-20 — Methodology release. §3.5 byte-sweep mandate added.
- v2.4.1 — 2026-05-20 — F-10: KDF default flipped to Argon2id.
- v2.4.2 — 2026-05-20 — F-11 closed: verbal probe-oracle eliminated.
- v2.4.3 — 2026-05-20 — F-12: encrypted archive comments. Byte sweep on
  1878-byte PQ-SDK+comment archive: **0/1878 undetected**.
- v2.4.4 — 2026-05-20 — Distribution packaging + reproducible `make dist`.
- v2.4.5 — 2026-05-20 — Packaging completion: RPM, Nix flake, DISTRIBUTION.md.
- v2.4.6 — 2026-05-20 — CI rewrite + THREAT_MODEL.md.
- v2.4.7 — 2026-05-20 — Manpage refresh and shell completions (bash, zsh,
  fish). Also corrected three stale banner strings that claimed PBKDF2 was
  the default KDF despite the v2.4.1 flip to Argon2id (user-visible text
  only; no behavioural change). No source changes that affect security
  posture; audit posture unchanged from v2.4.3.
- v2.4.8 — 2026-05-24 — Distro-friendly release. New `make check` target
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.0.0 — 2026-05-25 — MAJOR: Zupt → VaptVupt INPI Brasil trademark rename.
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.0.1 — 2026-05-26 — GUI license cleanup (removed MIT credit line;
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.0.2 — 2026-05-26 — F-13 closed: usage() string literal in
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.0.3 — 2026-05-26 — Static-analysis cleanup. cppcheck
  knownConditionTrueFalse findings closed in varint decoders
  (dead `&& (x&0x80)` AND-branch after preceding terminator-byte
  early-return). -Wconversion / -Wsign-conversion findings closed
  with explicit casts at two sites. Our 9-file non-vendored C now
  compiles clean under the union of strict GCC warnings including
  -Wconversion -Wsign-conversion -Werror. New regression test
  tests/test_static_analysis.sh (7 assertions) wired into make
  check and make test. Behaviour byte-identical; F-09 byte sweep
  still 0/1827 silent accepts. No source crypto changes.
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.1.0 — 2026-05-31 — VaptVupt codec 2.48.5 -> 2.53.3 (API
  byte-identical; 3 .c files changed). Inherits 6 upstream
  corrupt-input decoder memory-safety fixes (v2.52.4 + v2.53.2).
  F-14 closed: ASAN found a heap-buffer-overflow WRITE of size 32
  in OUR decode wrapper — decode buffers were malloc(uncompressed
  _size) with no slack, but the codec AVX2 over-copy needs >=32 B
  slack (documented contract in vaptvupt.h). Old codec never
  reached it; new wider AVX2 hot path does. Fixed with shared
  ZUPT_VV_DECODE_SLACK (64 B) guard on both single-threaded
  (zupt_format.c) and parallel (zupt_parallel.c) decode paths.
  Verified: ASAN 24/24 single-threaded + 15/15 multi-threaded;
  bit-flip fuzz 300 trials 0 crashes / 300 clean rejects. F-09
  byte sweep still 0/1827. vv_decoder.c scalar build made
  -Werror clean for aarch64/Termux. New test tests/test_vv_decode
  _slack.sh. Wire format unchanged (v1.6); 3.0.3 archives extract
  byte-exact.
  knownConditionTrueFalse findings closed in varint decoders
  (dead `&& (x&0x80)` AND-branch after preceding terminator-byte
  early-return). -Wconversion / -Wsign-conversion findings closed
  with explicit casts at two sites. Our 9-file non-vendored C now
  compiles clean under the union of strict GCC warnings including
  -Wconversion -Wsign-conversion -Werror. New regression test
  tests/test_static_analysis.sh (7 assertions) wired into make
  check and make test. Behaviour byte-identical; F-09 byte sweep
  still 0/1827 silent accepts. No source crypto changes.
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.2.0 — 2026-06-01 — SHA-256 hardware acceleration (Intel
  SHA-NI). New SHA256RNDS2/MSG1/MSG2 compression path with CPUID
  runtime dispatch (has_shani, CPUID.07H:EBX[29]). Accelerates the
  Encrypt-then-MAC second pass (HMAC-SHA256) and PBKDF2.
  Security-relevant property: SHA-NI is constant-time by
  construction (no data-dependent memory access or branches),
  strengthening the side-channel posture of HMAC verification over
  attacker-influenced ciphertext vs the scalar software path. No
  cryptographic-correctness change: same SHA-256, same HMAC, same
  Encrypt-then-MAC, same wire bytes (format v1.6 unchanged). NIST
  FIPS 180-4 vectors pass on both paths; the 64 SHA-NI round
  constants are verified bit-identical to the scalar K[] table.
  Speedup ([ESTIMATED] 3-8x) NOT measured in this release — the
  build host lacks SHA-NI; figure to be confirmed on SHA-NI
  hardware. Scalar fallback unchanged and remains the path on
  non-SHA-NI CPUs (incl. aarch64). F-09 byte sweep still 0/1827.
  byte-identical; 3 .c files changed). Inherits 6 upstream
  corrupt-input decoder memory-safety fixes (v2.52.4 + v2.53.2).
  F-14 closed: ASAN found a heap-buffer-overflow WRITE of size 32
  in OUR decode wrapper — decode buffers were malloc(uncompressed
  _size) with no slack, but the codec AVX2 over-copy needs >=32 B
  slack (documented contract in vaptvupt.h). Old codec never
  reached it; new wider AVX2 hot path does. Fixed with shared
  ZUPT_VV_DECODE_SLACK (64 B) guard on both single-threaded
  (zupt_format.c) and parallel (zupt_parallel.c) decode paths.
  Verified: ASAN 24/24 single-threaded + 15/15 multi-threaded;
  bit-flip fuzz 300 trials 0 crashes / 300 clean rejects. F-09
  byte sweep still 0/1827. vv_decoder.c scalar build made
  -Werror clean for aarch64/Termux. New test tests/test_vv_decode
  _slack.sh. Wire format unchanged (v1.6); 3.0.3 archives extract
  byte-exact.
  knownConditionTrueFalse findings closed in varint decoders
  (dead `&& (x&0x80)` AND-branch after preceding terminator-byte
  early-return). -Wconversion / -Wsign-conversion findings closed
  with explicit casts at two sites. Our 9-file non-vendored C now
  compiles clean under the union of strict GCC warnings including
  -Wconversion -Wsign-conversion -Werror. New regression test
  tests/test_static_analysis.sh (7 assertions) wired into make
  check and make test. Behaviour byte-identical; F-09 byte sweep
  still 0/1827 silent accepts. No source crypto changes.
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.3.0 — 2026-06-01 — Incremental HMAC-SHA256 for the per-block
  Encrypt-then-MAC hot path. ipad/opad key prefix folded once per
  keyring; MAC streamed (aad || nonce || ciphertext || seq) instead
  of concatenated into a malloc'd buffer. SECURITY-RELEVANT:
  identical authentication semantics — the MAC is byte-for-byte the
  same (RFC 2104 + SHA-256 Merkle-Damgard associativity), proven by
  RFC 4231 vectors, a new equivalence test, and byte-exact
  decryption of 3.2.x archives. Constant-time tag compares unchanged
  (byte-OR accumulator / Jasmin zupt_mac_verify_ct). F-09 byte sweep
  0/1827; F-06 1-bit HMAC fuzz 0/2000. Reduces secret-data heap
  footprint: the old path copied the full ciphertext into a second
  malloc'd buffer per block — now removed. No cryptographic-
  correctness change, no wire-format change (v1.6). ASan clean on
  both KDF paths.
  SHA-NI). New SHA256RNDS2/MSG1/MSG2 compression path with CPUID
  runtime dispatch (has_shani, CPUID.07H:EBX[29]). Accelerates the
  Encrypt-then-MAC second pass (HMAC-SHA256) and PBKDF2.
  Security-relevant property: SHA-NI is constant-time by
  construction (no data-dependent memory access or branches),
  strengthening the side-channel posture of HMAC verification over
  attacker-influenced ciphertext vs the scalar software path. No
  cryptographic-correctness change: same SHA-256, same HMAC, same
  Encrypt-then-MAC, same wire bytes (format v1.6 unchanged). NIST
  FIPS 180-4 vectors pass on both paths; the 64 SHA-NI round
  constants are verified bit-identical to the scalar K[] table.
  Speedup ([ESTIMATED] 3-8x) NOT measured in this release — the
  build host lacks SHA-NI; figure to be confirmed on SHA-NI
  hardware. Scalar fallback unchanged and remains the path on
  non-SHA-NI CPUs (incl. aarch64). F-09 byte sweep still 0/1827.
  byte-identical; 3 .c files changed). Inherits 6 upstream
  corrupt-input decoder memory-safety fixes (v2.52.4 + v2.53.2).
  F-14 closed: ASAN found a heap-buffer-overflow WRITE of size 32
  in OUR decode wrapper — decode buffers were malloc(uncompressed
  _size) with no slack, but the codec AVX2 over-copy needs >=32 B
  slack (documented contract in vaptvupt.h). Old codec never
  reached it; new wider AVX2 hot path does. Fixed with shared
  ZUPT_VV_DECODE_SLACK (64 B) guard on both single-threaded
  (zupt_format.c) and parallel (zupt_parallel.c) decode paths.
  Verified: ASAN 24/24 single-threaded + 15/15 multi-threaded;
  bit-flip fuzz 300 trials 0 crashes / 300 clean rejects. F-09
  byte sweep still 0/1827. vv_decoder.c scalar build made
  -Werror clean for aarch64/Termux. New test tests/test_vv_decode
  _slack.sh. Wire format unchanged (v1.6); 3.0.3 archives extract
  byte-exact.
  knownConditionTrueFalse findings closed in varint decoders
  (dead `&& (x&0x80)` AND-branch after preceding terminator-byte
  early-return). -Wconversion / -Wsign-conversion findings closed
  with explicit casts at two sites. Our 9-file non-vendored C now
  compiles clean under the union of strict GCC warnings including
  -Wconversion -Wsign-conversion -Werror. New regression test
  tests/test_static_analysis.sh (7 assertions) wired into make
  check and make test. Behaviour byte-identical; F-09 byte sweep
  still 0/1827 silent accepts. No source crypto changes.
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.4.0 — 2026-06-01 — F-15: Argon2id KDF parameter transparency.
  The 0x04 Argon2id enc-header recorded only [type|salt|nonce] and
  nothing about the KDF cost (the PBKDF2 header records its iteration
  count). New archives append a one-byte KDF profile descriptor at
  offset 33 (ZUPT_ARGON2_PROFILE_MODERATE), making the header self-
  describing so a reader always knows which Argon2id cost produced
  the archive — eliminating a silent-undecryptability risk if the
  preset ever changes. The descriptor is covered by the F-08 archive-
  integrity trailer (tamper-evident; a flipped byte fails decryption,
  verified). Additive + back-compatible: legacy 33-byte archives
  decrypt byte-exact; 33B and 34B headers derive identical keys;
  unknown profiles are refused fail-closed (no wrong-key guessing).
  Build-time SDK-drift guard: the F-15 test asserts the KDF is
  deterministic and meets a coarse memory-hard cost floor (>=20 ms),
  failing the build if libzuptsdk is swapped for a weak/stub Argon2id.
  No cryptographic-correctness change, no wire-format change (v1.6).
  F-09 byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000. Note: the
  explicit RFC 9106 zsdk_argon2id() is header-declared but NOT
  exported by the vendored libzuptsdk.so, so the cost is recorded in-
  band rather than re-parameterised; revisit if the SDK exports it.
  Encrypt-then-MAC hot path. ipad/opad key prefix folded once per
  keyring; MAC streamed (aad || nonce || ciphertext || seq) instead
  of concatenated into a malloc'd buffer. SECURITY-RELEVANT:
  identical authentication semantics — the MAC is byte-for-byte the
  same (RFC 2104 + SHA-256 Merkle-Damgard associativity), proven by
  RFC 4231 vectors, a new equivalence test, and byte-exact
  decryption of 3.2.x archives. Constant-time tag compares unchanged
  (byte-OR accumulator / Jasmin zupt_mac_verify_ct). F-09 byte sweep
  0/1827; F-06 1-bit HMAC fuzz 0/2000. Reduces secret-data heap
  footprint: the old path copied the full ciphertext into a second
  malloc'd buffer per block — now removed. No cryptographic-
  correctness change, no wire-format change (v1.6). ASan clean on
  both KDF paths.
  SHA-NI). New SHA256RNDS2/MSG1/MSG2 compression path with CPUID
  runtime dispatch (has_shani, CPUID.07H:EBX[29]). Accelerates the
  Encrypt-then-MAC second pass (HMAC-SHA256) and PBKDF2.
  Security-relevant property: SHA-NI is constant-time by
  construction (no data-dependent memory access or branches),
  strengthening the side-channel posture of HMAC verification over
  attacker-influenced ciphertext vs the scalar software path. No
  cryptographic-correctness change: same SHA-256, same HMAC, same
  Encrypt-then-MAC, same wire bytes (format v1.6 unchanged). NIST
  FIPS 180-4 vectors pass on both paths; the 64 SHA-NI round
  constants are verified bit-identical to the scalar K[] table.
  Speedup ([ESTIMATED] 3-8x) NOT measured in this release — the
  build host lacks SHA-NI; figure to be confirmed on SHA-NI
  hardware. Scalar fallback unchanged and remains the path on
  non-SHA-NI CPUs (incl. aarch64). F-09 byte sweep still 0/1827.
  byte-identical; 3 .c files changed). Inherits 6 upstream
  corrupt-input decoder memory-safety fixes (v2.52.4 + v2.53.2).
  F-14 closed: ASAN found a heap-buffer-overflow WRITE of size 32
  in OUR decode wrapper — decode buffers were malloc(uncompressed
  _size) with no slack, but the codec AVX2 over-copy needs >=32 B
  slack (documented contract in vaptvupt.h). Old codec never
  reached it; new wider AVX2 hot path does. Fixed with shared
  ZUPT_VV_DECODE_SLACK (64 B) guard on both single-threaded
  (zupt_format.c) and parallel (zupt_parallel.c) decode paths.
  Verified: ASAN 24/24 single-threaded + 15/15 multi-threaded;
  bit-flip fuzz 300 trials 0 crashes / 300 clean rejects. F-09
  byte sweep still 0/1827. vv_decoder.c scalar build made
  -Werror clean for aarch64/Termux. New test tests/test_vv_decode
  _slack.sh. Wire format unchanged (v1.6); 3.0.3 archives extract
  byte-exact.
  knownConditionTrueFalse findings closed in varint decoders
  (dead `&& (x&0x80)` AND-branch after preceding terminator-byte
  early-return). -Wconversion / -Wsign-conversion findings closed
  with explicit casts at two sites. Our 9-file non-vendored C now
  compiles clean under the union of strict GCC warnings including
  -Wconversion -Wsign-conversion -Werror. New regression test
  tests/test_static_analysis.sh (7 assertions) wired into make
  check and make test. Behaviour byte-identical; F-09 byte sweep
  still 0/1827 silent accepts. No source crypto changes.
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.5.0 — 2026-06-01 — Measured constant-time MAC comparison
  (dudect-style). The MAC tag compare — the most timing-sensitive
  operation, where a leak is a forgery oracle — was carried as three
  duplicated inline byte-OR loops marked CT-REQUIRED but never
  measured. Consolidated into one audited primitive zupt_ct_memeq
  (volatile OR-accumulate, no early exit, branch-free fold), used by
  the v1.6 strict decrypt path and the F-08 archive-integrity-trailer
  check. New dudect-style timing test (tests/test_ct_timing.c):
  Welch t-test over fixed-equal vs random-differing tag classes,
  built at -O2 so it exercises the shipped code (incl. that the
  volatile sink survives the optimiser). Verdict is environment-
  relative: a leaky-memcmp positive control must show a clear leak in
  the same environment, and zupt_ct_memeq must show <=20% of that
  signal (measured ~1%; median of 5 runs; INCONCLUSIVE rather than
  vacuous-pass if the host is too coarse). A reintroduced early-
  return/branch pushes the ratio toward 1.0 and fails. This turns an
  asserted CT property into a measured one + CI regression guard.
  The formally-verified Jasmin zupt_mac_verify_ct path (v1.4/v1.5
  legacy compare) and the F-06 two-candidate fold are unchanged. No
  cryptographic-correctness change, no wire-format change (v1.6).
  F-09 byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000.
  The 0x04 Argon2id enc-header recorded only [type|salt|nonce] and
  nothing about the KDF cost (the PBKDF2 header records its iteration
  count). New archives append a one-byte KDF profile descriptor at
  offset 33 (ZUPT_ARGON2_PROFILE_MODERATE), making the header self-
  describing so a reader always knows which Argon2id cost produced
  the archive — eliminating a silent-undecryptability risk if the
  preset ever changes. The descriptor is covered by the F-08 archive-
  integrity trailer (tamper-evident; a flipped byte fails decryption,
  verified). Additive + back-compatible: legacy 33-byte archives
  decrypt byte-exact; 33B and 34B headers derive identical keys;
  unknown profiles are refused fail-closed (no wrong-key guessing).
  Build-time SDK-drift guard: the F-15 test asserts the KDF is
  deterministic and meets a coarse memory-hard cost floor (>=20 ms),
  failing the build if libzuptsdk is swapped for a weak/stub Argon2id.
  No cryptographic-correctness change, no wire-format change (v1.6).
  F-09 byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000. Note: the
  explicit RFC 9106 zsdk_argon2id() is header-declared but NOT
  exported by the vendored libzuptsdk.so, so the cost is recorded in-
  band rather than re-parameterised; revisit if the SDK exports it.
  Encrypt-then-MAC hot path. ipad/opad key prefix folded once per
  keyring; MAC streamed (aad || nonce || ciphertext || seq) instead
  of concatenated into a malloc'd buffer. SECURITY-RELEVANT:
  identical authentication semantics — the MAC is byte-for-byte the
  same (RFC 2104 + SHA-256 Merkle-Damgard associativity), proven by
  RFC 4231 vectors, a new equivalence test, and byte-exact
  decryption of 3.2.x archives. Constant-time tag compares unchanged
  (byte-OR accumulator / Jasmin zupt_mac_verify_ct). F-09 byte sweep
  0/1827; F-06 1-bit HMAC fuzz 0/2000. Reduces secret-data heap
  footprint: the old path copied the full ciphertext into a second
  malloc'd buffer per block — now removed. No cryptographic-
  correctness change, no wire-format change (v1.6). ASan clean on
  both KDF paths.
  SHA-NI). New SHA256RNDS2/MSG1/MSG2 compression path with CPUID
  runtime dispatch (has_shani, CPUID.07H:EBX[29]). Accelerates the
  Encrypt-then-MAC second pass (HMAC-SHA256) and PBKDF2.
  Security-relevant property: SHA-NI is constant-time by
  construction (no data-dependent memory access or branches),
  strengthening the side-channel posture of HMAC verification over
  attacker-influenced ciphertext vs the scalar software path. No
  cryptographic-correctness change: same SHA-256, same HMAC, same
  Encrypt-then-MAC, same wire bytes (format v1.6 unchanged). NIST
  FIPS 180-4 vectors pass on both paths; the 64 SHA-NI round
  constants are verified bit-identical to the scalar K[] table.
  Speedup ([ESTIMATED] 3-8x) NOT measured in this release — the
  build host lacks SHA-NI; figure to be confirmed on SHA-NI
  hardware. Scalar fallback unchanged and remains the path on
  non-SHA-NI CPUs (incl. aarch64). F-09 byte sweep still 0/1827.
  byte-identical; 3 .c files changed). Inherits 6 upstream
  corrupt-input decoder memory-safety fixes (v2.52.4 + v2.53.2).
  F-14 closed: ASAN found a heap-buffer-overflow WRITE of size 32
  in OUR decode wrapper — decode buffers were malloc(uncompressed
  _size) with no slack, but the codec AVX2 over-copy needs >=32 B
  slack (documented contract in vaptvupt.h). Old codec never
  reached it; new wider AVX2 hot path does. Fixed with shared
  ZUPT_VV_DECODE_SLACK (64 B) guard on both single-threaded
  (zupt_format.c) and parallel (zupt_parallel.c) decode paths.
  Verified: ASAN 24/24 single-threaded + 15/15 multi-threaded;
  bit-flip fuzz 300 trials 0 crashes / 300 clean rejects. F-09
  byte sweep still 0/1827. vv_decoder.c scalar build made
  -Werror clean for aarch64/Termux. New test tests/test_vv_decode
  _slack.sh. Wire format unchanged (v1.6); 3.0.3 archives extract
  byte-exact.
  knownConditionTrueFalse findings closed in varint decoders
  (dead `&& (x&0x80)` AND-branch after preceding terminator-byte
  early-return). -Wconversion / -Wsign-conversion findings closed
  with explicit casts at two sites. Our 9-file non-vendored C now
  compiles clean under the union of strict GCC warnings including
  -Wconversion -Wsign-conversion -Werror. New regression test
  tests/test_static_analysis.sh (7 assertions) wired into make
  check and make test. Behaviour byte-identical; F-09 byte sweep
  still 0/1827 silent accepts. No source crypto changes.
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.6.0 — 2026-06-01 — NIST SP 800-38A AES-256-CTR known-answer
  vectors + ML-KEM self-test fixes. AES-256-CTR — the bulk cipher —
  previously had only indirect roundtrip coverage; added the
  canonical SP 800-38A F.5.5 (encrypt) and F.5.6 (decrypt) vectors,
  validating zupt_aes256_ctr against the standard on both the Jasmin
  AES-NI path (zupt_aes256_ctr4 + zupt_aes256_blk) and the C T-table
  fallback. Both match exactly, confirming the Jasmin single-block
  AES is correct vs the standard (retires the stale stack-offset
  concern for zupt_aes256_blk). Also fixed two ML-KEM-768 self-test
  bugs: (1) an inverted result check in test_vectors that printed OK
  when the self-test returned failure — it had been passing
  vacuously; (2) the NTT roundtrip self-test asserted a false
  ntt∘inv_ntt == identity (this pqcrystals/Kyber Montgomery
  convention recovers each coefficient scaled by R^-1 mod q = 169),
  now rewritten to assert the true consistent-linear-scaling
  invariant, which still catches genuine NTT bugs and no longer
  emits a misleading stderr "NTT roundtrip FAILED". ML-KEM
  correctness end-to-end was never affected — the K-PKE, KEM, and
  FIPS 203 roundtrip vectors and implicit-rejection all pass. No
  source-crypto behaviour change, no wire-format change (v1.6).
  test_vectors now 16 passed / 0 failed (was 14, one vacuous). F-09
  byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000.
  (dudect-style). The MAC tag compare — the most timing-sensitive
  operation, where a leak is a forgery oracle — was carried as three
  duplicated inline byte-OR loops marked CT-REQUIRED but never
  measured. Consolidated into one audited primitive zupt_ct_memeq
  (volatile OR-accumulate, no early exit, branch-free fold), used by
  the v1.6 strict decrypt path and the F-08 archive-integrity-trailer
  check. New dudect-style timing test (tests/test_ct_timing.c):
  Welch t-test over fixed-equal vs random-differing tag classes,
  built at -O2 so it exercises the shipped code (incl. that the
  volatile sink survives the optimiser). Verdict is environment-
  relative: a leaky-memcmp positive control must show a clear leak in
  the same environment, and zupt_ct_memeq must show <=20% of that
  signal (measured ~1%; median of 5 runs; INCONCLUSIVE rather than
  vacuous-pass if the host is too coarse). A reintroduced early-
  return/branch pushes the ratio toward 1.0 and fails. This turns an
  asserted CT property into a measured one + CI regression guard.
  The formally-verified Jasmin zupt_mac_verify_ct path (v1.4/v1.5
  legacy compare) and the F-06 two-candidate fold are unchanged. No
  cryptographic-correctness change, no wire-format change (v1.6).
  F-09 byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000.
  The 0x04 Argon2id enc-header recorded only [type|salt|nonce] and
  nothing about the KDF cost (the PBKDF2 header records its iteration
  count). New archives append a one-byte KDF profile descriptor at
  offset 33 (ZUPT_ARGON2_PROFILE_MODERATE), making the header self-
  describing so a reader always knows which Argon2id cost produced
  the archive — eliminating a silent-undecryptability risk if the
  preset ever changes. The descriptor is covered by the F-08 archive-
  integrity trailer (tamper-evident; a flipped byte fails decryption,
  verified). Additive + back-compatible: legacy 33-byte archives
  decrypt byte-exact; 33B and 34B headers derive identical keys;
  unknown profiles are refused fail-closed (no wrong-key guessing).
  Build-time SDK-drift guard: the F-15 test asserts the KDF is
  deterministic and meets a coarse memory-hard cost floor (>=20 ms),
  failing the build if libzuptsdk is swapped for a weak/stub Argon2id.
  No cryptographic-correctness change, no wire-format change (v1.6).
  F-09 byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000. Note: the
  explicit RFC 9106 zsdk_argon2id() is header-declared but NOT
  exported by the vendored libzuptsdk.so, so the cost is recorded in-
  band rather than re-parameterised; revisit if the SDK exports it.
  Encrypt-then-MAC hot path. ipad/opad key prefix folded once per
  keyring; MAC streamed (aad || nonce || ciphertext || seq) instead
  of concatenated into a malloc'd buffer. SECURITY-RELEVANT:
  identical authentication semantics — the MAC is byte-for-byte the
  same (RFC 2104 + SHA-256 Merkle-Damgard associativity), proven by
  RFC 4231 vectors, a new equivalence test, and byte-exact
  decryption of 3.2.x archives. Constant-time tag compares unchanged
  (byte-OR accumulator / Jasmin zupt_mac_verify_ct). F-09 byte sweep
  0/1827; F-06 1-bit HMAC fuzz 0/2000. Reduces secret-data heap
  footprint: the old path copied the full ciphertext into a second
  malloc'd buffer per block — now removed. No cryptographic-
  correctness change, no wire-format change (v1.6). ASan clean on
  both KDF paths.
  SHA-NI). New SHA256RNDS2/MSG1/MSG2 compression path with CPUID
  runtime dispatch (has_shani, CPUID.07H:EBX[29]). Accelerates the
  Encrypt-then-MAC second pass (HMAC-SHA256) and PBKDF2.
  Security-relevant property: SHA-NI is constant-time by
  construction (no data-dependent memory access or branches),
  strengthening the side-channel posture of HMAC verification over
  attacker-influenced ciphertext vs the scalar software path. No
  cryptographic-correctness change: same SHA-256, same HMAC, same
  Encrypt-then-MAC, same wire bytes (format v1.6 unchanged). NIST
  FIPS 180-4 vectors pass on both paths; the 64 SHA-NI round
  constants are verified bit-identical to the scalar K[] table.
  Speedup ([ESTIMATED] 3-8x) NOT measured in this release — the
  build host lacks SHA-NI; figure to be confirmed on SHA-NI
  hardware. Scalar fallback unchanged and remains the path on
  non-SHA-NI CPUs (incl. aarch64). F-09 byte sweep still 0/1827.
  byte-identical; 3 .c files changed). Inherits 6 upstream
  corrupt-input decoder memory-safety fixes (v2.52.4 + v2.53.2).
  F-14 closed: ASAN found a heap-buffer-overflow WRITE of size 32
  in OUR decode wrapper — decode buffers were malloc(uncompressed
  _size) with no slack, but the codec AVX2 over-copy needs >=32 B
  slack (documented contract in vaptvupt.h). Old codec never
  reached it; new wider AVX2 hot path does. Fixed with shared
  ZUPT_VV_DECODE_SLACK (64 B) guard on both single-threaded
  (zupt_format.c) and parallel (zupt_parallel.c) decode paths.
  Verified: ASAN 24/24 single-threaded + 15/15 multi-threaded;
  bit-flip fuzz 300 trials 0 crashes / 300 clean rejects. F-09
  byte sweep still 0/1827. vv_decoder.c scalar build made
  -Werror clean for aarch64/Termux. New test tests/test_vv_decode
  _slack.sh. Wire format unchanged (v1.6); 3.0.3 archives extract
  byte-exact.
  knownConditionTrueFalse findings closed in varint decoders
  (dead `&& (x&0x80)` AND-branch after preceding terminator-byte
  early-return). -Wconversion / -Wsign-conversion findings closed
  with explicit casts at two sites. Our 9-file non-vendored C now
  compiles clean under the union of strict GCC warnings including
  -Wconversion -Wsign-conversion -Werror. New regression test
  tests/test_static_analysis.sh (7 assertions) wired into make
  check and make test. Behaviour byte-identical; F-09 byte sweep
  still 0/1827 silent accepts. No source crypto changes.
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v3.7.0 — 2026-06-01 — ML-KEM-768 decapsulation comparison routed
  through the audited constant-time primitive. The implicit-
  rejection check (received ct vs re-encrypted ct', 1088 bytes) was
  an inline byte-OR loop marked CT-REQUIRED but never measured and
  not sharing the zupt_ct_memeq primitive introduced in 3.5.0. A
  timing leak there is a KEM decapsulation oracle (valid vs invalid
  ciphertext) that breaks IND-CCA2. It now calls
  zupt_ct_memeq(ct, ct_prime, 1088); the fail bit is (1 - equal) so
  ML-KEM output is byte-identical (FIPS 203 roundtrip, implicit-
  rejection vector, PQ-hybrid roundtrip, wrong-key rejection all
  pass). This was the LAST security-critical comparison using a
  bespoke inline loop — MAC tag, F-08 trailer, and ML-KEM decaps now
  all route through one audited, length-independent primitive.
  tests/test_ct_timing extended to 1088 bytes with a source-routing
  guard. HONEST SCOPING: the 1088-byte dudect numbers are reported
  informational, not pass/fail — at that size on a shared vCPU the
  signal is memory-dominated and memcmp is not a cleanly-leaking
  control, so the 32-byte environment-relative ratio does not
  transfer. Constant-timeness of the 1088-byte compare instead
  follows from (a) the 32-byte pass proving zupt_ct_memeq is CT,
  (b) zupt_ct_memeq being length-independent by construction
  (OR-accumulate, no early exit, no data-dependent branch), and
  (c) the source-routing guard confirming decaps uses it. No
  cryptographic-correctness change, no wire-format change (v1.6).
  test_vectors 16/0; F-09 byte sweep 0/1827; F-06 0/2000.
  vectors + ML-KEM self-test fixes. AES-256-CTR — the bulk cipher —
  previously had only indirect roundtrip coverage; added the
  canonical SP 800-38A F.5.5 (encrypt) and F.5.6 (decrypt) vectors,
  validating zupt_aes256_ctr against the standard on both the Jasmin
  AES-NI path (zupt_aes256_ctr4 + zupt_aes256_blk) and the C T-table
  fallback. Both match exactly, confirming the Jasmin single-block
  AES is correct vs the standard (retires the stale stack-offset
  concern for zupt_aes256_blk). Also fixed two ML-KEM-768 self-test
  bugs: (1) an inverted result check in test_vectors that printed OK
  when the self-test returned failure — it had been passing
  vacuously; (2) the NTT roundtrip self-test asserted a false
  ntt∘inv_ntt == identity (this pqcrystals/Kyber Montgomery
  convention recovers each coefficient scaled by R^-1 mod q = 169),
  now rewritten to assert the true consistent-linear-scaling
  invariant, which still catches genuine NTT bugs and no longer
  emits a misleading stderr "NTT roundtrip FAILED". ML-KEM
  correctness end-to-end was never affected — the K-PKE, KEM, and
  FIPS 203 roundtrip vectors and implicit-rejection all pass. No
  source-crypto behaviour change, no wire-format change (v1.6).
  test_vectors now 16 passed / 0 failed (was 14, one vacuous). F-09
  byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000.
  (dudect-style). The MAC tag compare — the most timing-sensitive
  operation, where a leak is a forgery oracle — was carried as three
  duplicated inline byte-OR loops marked CT-REQUIRED but never
  measured. Consolidated into one audited primitive zupt_ct_memeq
  (volatile OR-accumulate, no early exit, branch-free fold), used by
  the v1.6 strict decrypt path and the F-08 archive-integrity-trailer
  check. New dudect-style timing test (tests/test_ct_timing.c):
  Welch t-test over fixed-equal vs random-differing tag classes,
  built at -O2 so it exercises the shipped code (incl. that the
  volatile sink survives the optimiser). Verdict is environment-
  relative: a leaky-memcmp positive control must show a clear leak in
  the same environment, and zupt_ct_memeq must show <=20% of that
  signal (measured ~1%; median of 5 runs; INCONCLUSIVE rather than
  vacuous-pass if the host is too coarse). A reintroduced early-
  return/branch pushes the ratio toward 1.0 and fails. This turns an
  asserted CT property into a measured one + CI regression guard.
  The formally-verified Jasmin zupt_mac_verify_ct path (v1.4/v1.5
  legacy compare) and the F-06 two-candidate fold are unchanged. No
  cryptographic-correctness change, no wire-format change (v1.6).
  F-09 byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000.
  The 0x04 Argon2id enc-header recorded only [type|salt|nonce] and
  nothing about the KDF cost (the PBKDF2 header records its iteration
  count). New archives append a one-byte KDF profile descriptor at
  offset 33 (ZUPT_ARGON2_PROFILE_MODERATE), making the header self-
  describing so a reader always knows which Argon2id cost produced
  the archive — eliminating a silent-undecryptability risk if the
  preset ever changes. The descriptor is covered by the F-08 archive-
  integrity trailer (tamper-evident; a flipped byte fails decryption,
  verified). Additive + back-compatible: legacy 33-byte archives
  decrypt byte-exact; 33B and 34B headers derive identical keys;
  unknown profiles are refused fail-closed (no wrong-key guessing).
  Build-time SDK-drift guard: the F-15 test asserts the KDF is
  deterministic and meets a coarse memory-hard cost floor (>=20 ms),
  failing the build if libzuptsdk is swapped for a weak/stub Argon2id.
  No cryptographic-correctness change, no wire-format change (v1.6).
  F-09 byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000. Note: the
  explicit RFC 9106 zsdk_argon2id() is header-declared but NOT
  exported by the vendored libzuptsdk.so, so the cost is recorded in-
  band rather than re-parameterised; revisit if the SDK exports it.
  Encrypt-then-MAC hot path. ipad/opad key prefix folded once per
  keyring; MAC streamed (aad || nonce || ciphertext || seq) instead
  of concatenated into a malloc'd buffer. SECURITY-RELEVANT:
  identical authentication semantics — the MAC is byte-for-byte the
  same (RFC 2104 + SHA-256 Merkle-Damgard associativity), proven by
  RFC 4231 vectors, a new equivalence test, and byte-exact
  decryption of 3.2.x archives. Constant-time tag compares unchanged
  (byte-OR accumulator / Jasmin zupt_mac_verify_ct). F-09 byte sweep
  0/1827; F-06 1-bit HMAC fuzz 0/2000. Reduces secret-data heap
  footprint: the old path copied the full ciphertext into a second
  malloc'd buffer per block — now removed. No cryptographic-
  correctness change, no wire-format change (v1.6). ASan clean on
  both KDF paths.
  SHA-NI). New SHA256RNDS2/MSG1/MSG2 compression path with CPUID
  runtime dispatch (has_shani, CPUID.07H:EBX[29]). Accelerates the
  Encrypt-then-MAC second pass (HMAC-SHA256) and PBKDF2.
  Security-relevant property: SHA-NI is constant-time by
  construction (no data-dependent memory access or branches),
  strengthening the side-channel posture of HMAC verification over
  attacker-influenced ciphertext vs the scalar software path. No
  cryptographic-correctness change: same SHA-256, same HMAC, same
  Encrypt-then-MAC, same wire bytes (format v1.6 unchanged). NIST
  FIPS 180-4 vectors pass on both paths; the 64 SHA-NI round
  constants are verified bit-identical to the scalar K[] table.
  Speedup ([ESTIMATED] 3-8x) NOT measured in this release — the
  build host lacks SHA-NI; figure to be confirmed on SHA-NI
  hardware. Scalar fallback unchanged and remains the path on
  non-SHA-NI CPUs (incl. aarch64). F-09 byte sweep still 0/1827.
  byte-identical; 3 .c files changed). Inherits 6 upstream
  corrupt-input decoder memory-safety fixes (v2.52.4 + v2.53.2).
  F-14 closed: ASAN found a heap-buffer-overflow WRITE of size 32
  in OUR decode wrapper — decode buffers were malloc(uncompressed
  _size) with no slack, but the codec AVX2 over-copy needs >=32 B
  slack (documented contract in vaptvupt.h). Old codec never
  reached it; new wider AVX2 hot path does. Fixed with shared
  ZUPT_VV_DECODE_SLACK (64 B) guard on both single-threaded
  (zupt_format.c) and parallel (zupt_parallel.c) decode paths.
  Verified: ASAN 24/24 single-threaded + 15/15 multi-threaded;
  bit-flip fuzz 300 trials 0 crashes / 300 clean rejects. F-09
  byte sweep still 0/1827. vv_decoder.c scalar build made
  -Werror clean for aarch64/Termux. New test tests/test_vv_decode
  _slack.sh. Wire format unchanged (v1.6); 3.0.3 archives extract
  byte-exact.
  knownConditionTrueFalse findings closed in varint decoders
  (dead `&& (x&0x80)` AND-branch after preceding terminator-byte
  early-return). -Wconversion / -Wsign-conversion findings closed
  with explicit casts at two sites. Our 9-file non-vendored C now
  compiles clean under the union of strict GCC warnings including
  -Wconversion -Wsign-conversion -Werror. New regression test
  tests/test_static_analysis.sh (7 assertions) wired into make
  check and make test. Behaviour byte-identical; F-09 byte sweep
  still 0/1827 silent accepts. No source crypto changes.
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

- v4.0.0 — 2026-06-10 — Stack integration: codec → canonical 2.60.4
  (security release; OOB heap write in AVX2 exact-size decode fixed;
  CBMC-verified BCJ). F-16 found, disclosed, fixed (see Findings). New
  --pq-box mode via vendored libpqvaptvupt 0.6.0 (HKDF-SHA256
  domain-separated combiner; 13/13 adversarial checks; ASan/UBSan
  clean). New exact-content_size decode regression (80 cases, ASan).
  SHA-NI measured 5.8× same-box; v3.2.0 estimate retired. Clang strict
  build restored (as(1) for Jasmin .s). 8-mode back-compat byte-exact.
- v4.0.0 — 2026-06-10 — F-16: data loss in ≤3.8.0 BCJ encoding
  (pre-existing; found by the 4.0.0 back-compat matrix; fixed by the
  codec move to canonical 2.60.4). The ≤3.8.0 tree vendored a divergent
  pre-release BCJ (upstream 2.53.3 has no BCJ; it landed in 2.53.4).
  On BCJ-detected executable content at L8/L9 the old encoder emitted
  streams that no decoder accepts — including 3.8.0 itself (verified:
  the 3.8.0 binary fails on the archive it just wrote; defect is at
  write time, deterministic on the binary fixture). L≤7 and non-BCJ
  content unaffected: the 8-mode matrix (plain L1/L5/L9, store,
  Argon2id, PBKDF2, --pq, --pq-sdk) decodes byte-exact under 4.0.0.
  Remediation: re-create affected archives with ≥4.0.0 and verify
  extraction before deleting sources. Regression guard:
  tests/test_codec_exact_size.sh includes tool-level BCJ roundtrips
  (L5/L9, real ELF fixture) plus 80 exact-size codec decodes under
  ASan covering the upstream OOB fix class. Forward-compat note:
  ≤3.8.0 cannot read 4.0.0 archives where the auto-filter fired
  (L3+ on ELF/PE/Mach-O); upgrade readers first in mixed fleets.

- v3.8.0 — 2026-06-01 — Documentation-only release: consolidated
  measured benchmarks (BENCHMARKS.md). No source, cryptographic, or
  wire-format change — the binary is identical in behaviour to
  3.7.0 (format v1.6). Publishes a complete reproducible benchmark
  set (compression ratio/throughput, encode-speed-vs-level, the
  KDF-vs-per-block crypto overhead split, and a head-to-head ratio
  comparison against zstd that shows where VaptVupt loses) with the
  test machine and method stated per table. The SHA-NI speedup is
  explicitly marked [ESTIMATED] as the test box has no SHA-NI. No
  new findings; all prior guarantees unchanged: test_vectors 16/0,
  F-09 byte sweep 0/1827, F-06 1-bit HMAC fuzz 0/2000, every
  security-critical comparison through the audited constant-time
  primitive.
  through the audited constant-time primitive. The implicit-
  rejection check (received ct vs re-encrypted ct', 1088 bytes) was
  an inline byte-OR loop marked CT-REQUIRED but never measured and
  not sharing the zupt_ct_memeq primitive introduced in 3.5.0. A
  timing leak there is a KEM decapsulation oracle (valid vs invalid
  ciphertext) that breaks IND-CCA2. It now calls
  zupt_ct_memeq(ct, ct_prime, 1088); the fail bit is (1 - equal) so
  ML-KEM output is byte-identical (FIPS 203 roundtrip, implicit-
  rejection vector, PQ-hybrid roundtrip, wrong-key rejection all
  pass). This was the LAST security-critical comparison using a
  bespoke inline loop — MAC tag, F-08 trailer, and ML-KEM decaps now
  all route through one audited, length-independent primitive.
  tests/test_ct_timing extended to 1088 bytes with a source-routing
  guard. HONEST SCOPING: the 1088-byte dudect numbers are reported
  informational, not pass/fail — at that size on a shared vCPU the
  signal is memory-dominated and memcmp is not a cleanly-leaking
  control, so the 32-byte environment-relative ratio does not
  transfer. Constant-timeness of the 1088-byte compare instead
  follows from (a) the 32-byte pass proving zupt_ct_memeq is CT,
  (b) zupt_ct_memeq being length-independent by construction
  (OR-accumulate, no early exit, no data-dependent branch), and
  (c) the source-routing guard confirming decaps uses it. No
  cryptographic-correctness change, no wire-format change (v1.6).
  test_vectors 16/0; F-09 byte sweep 0/1827; F-06 0/2000.
  vectors + ML-KEM self-test fixes. AES-256-CTR — the bulk cipher —
  previously had only indirect roundtrip coverage; added the
  canonical SP 800-38A F.5.5 (encrypt) and F.5.6 (decrypt) vectors,
  validating zupt_aes256_ctr against the standard on both the Jasmin
  AES-NI path (zupt_aes256_ctr4 + zupt_aes256_blk) and the C T-table
  fallback. Both match exactly, confirming the Jasmin single-block
  AES is correct vs the standard (retires the stale stack-offset
  concern for zupt_aes256_blk). Also fixed two ML-KEM-768 self-test
  bugs: (1) an inverted result check in test_vectors that printed OK
  when the self-test returned failure — it had been passing
  vacuously; (2) the NTT roundtrip self-test asserted a false
  ntt∘inv_ntt == identity (this pqcrystals/Kyber Montgomery
  convention recovers each coefficient scaled by R^-1 mod q = 169),
  now rewritten to assert the true consistent-linear-scaling
  invariant, which still catches genuine NTT bugs and no longer
  emits a misleading stderr "NTT roundtrip FAILED". ML-KEM
  correctness end-to-end was never affected — the K-PKE, KEM, and
  FIPS 203 roundtrip vectors and implicit-rejection all pass. No
  source-crypto behaviour change, no wire-format change (v1.6).
  test_vectors now 16 passed / 0 failed (was 14, one vacuous). F-09
  byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000.
  (dudect-style). The MAC tag compare — the most timing-sensitive
  operation, where a leak is a forgery oracle — was carried as three
  duplicated inline byte-OR loops marked CT-REQUIRED but never
  measured. Consolidated into one audited primitive zupt_ct_memeq
  (volatile OR-accumulate, no early exit, branch-free fold), used by
  the v1.6 strict decrypt path and the F-08 archive-integrity-trailer
  check. New dudect-style timing test (tests/test_ct_timing.c):
  Welch t-test over fixed-equal vs random-differing tag classes,
  built at -O2 so it exercises the shipped code (incl. that the
  volatile sink survives the optimiser). Verdict is environment-
  relative: a leaky-memcmp positive control must show a clear leak in
  the same environment, and zupt_ct_memeq must show <=20% of that
  signal (measured ~1%; median of 5 runs; INCONCLUSIVE rather than
  vacuous-pass if the host is too coarse). A reintroduced early-
  return/branch pushes the ratio toward 1.0 and fails. This turns an
  asserted CT property into a measured one + CI regression guard.
  The formally-verified Jasmin zupt_mac_verify_ct path (v1.4/v1.5
  legacy compare) and the F-06 two-candidate fold are unchanged. No
  cryptographic-correctness change, no wire-format change (v1.6).
  F-09 byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000.
  The 0x04 Argon2id enc-header recorded only [type|salt|nonce] and
  nothing about the KDF cost (the PBKDF2 header records its iteration
  count). New archives append a one-byte KDF profile descriptor at
  offset 33 (ZUPT_ARGON2_PROFILE_MODERATE), making the header self-
  describing so a reader always knows which Argon2id cost produced
  the archive — eliminating a silent-undecryptability risk if the
  preset ever changes. The descriptor is covered by the F-08 archive-
  integrity trailer (tamper-evident; a flipped byte fails decryption,
  verified). Additive + back-compatible: legacy 33-byte archives
  decrypt byte-exact; 33B and 34B headers derive identical keys;
  unknown profiles are refused fail-closed (no wrong-key guessing).
  Build-time SDK-drift guard: the F-15 test asserts the KDF is
  deterministic and meets a coarse memory-hard cost floor (>=20 ms),
  failing the build if libzuptsdk is swapped for a weak/stub Argon2id.
  No cryptographic-correctness change, no wire-format change (v1.6).
  F-09 byte sweep 0/1827; F-06 1-bit HMAC fuzz 0/2000. Note: the
  explicit RFC 9106 zsdk_argon2id() is header-declared but NOT
  exported by the vendored libzuptsdk.so, so the cost is recorded in-
  band rather than re-parameterised; revisit if the SDK exports it.
  Encrypt-then-MAC hot path. ipad/opad key prefix folded once per
  keyring; MAC streamed (aad || nonce || ciphertext || seq) instead
  of concatenated into a malloc'd buffer. SECURITY-RELEVANT:
  identical authentication semantics — the MAC is byte-for-byte the
  same (RFC 2104 + SHA-256 Merkle-Damgard associativity), proven by
  RFC 4231 vectors, a new equivalence test, and byte-exact
  decryption of 3.2.x archives. Constant-time tag compares unchanged
  (byte-OR accumulator / Jasmin zupt_mac_verify_ct). F-09 byte sweep
  0/1827; F-06 1-bit HMAC fuzz 0/2000. Reduces secret-data heap
  footprint: the old path copied the full ciphertext into a second
  malloc'd buffer per block — now removed. No cryptographic-
  correctness change, no wire-format change (v1.6). ASan clean on
  both KDF paths.
  SHA-NI). New SHA256RNDS2/MSG1/MSG2 compression path with CPUID
  runtime dispatch (has_shani, CPUID.07H:EBX[29]). Accelerates the
  Encrypt-then-MAC second pass (HMAC-SHA256) and PBKDF2.
  Security-relevant property: SHA-NI is constant-time by
  construction (no data-dependent memory access or branches),
  strengthening the side-channel posture of HMAC verification over
  attacker-influenced ciphertext vs the scalar software path. No
  cryptographic-correctness change: same SHA-256, same HMAC, same
  Encrypt-then-MAC, same wire bytes (format v1.6 unchanged). NIST
  FIPS 180-4 vectors pass on both paths; the 64 SHA-NI round
  constants are verified bit-identical to the scalar K[] table.
  Speedup ([ESTIMATED] 3-8x) NOT measured in this release — the
  build host lacks SHA-NI; figure to be confirmed on SHA-NI
  hardware. Scalar fallback unchanged and remains the path on
  non-SHA-NI CPUs (incl. aarch64). F-09 byte sweep still 0/1827.
  byte-identical; 3 .c files changed). Inherits 6 upstream
  corrupt-input decoder memory-safety fixes (v2.52.4 + v2.53.2).
  F-14 closed: ASAN found a heap-buffer-overflow WRITE of size 32
  in OUR decode wrapper — decode buffers were malloc(uncompressed
  _size) with no slack, but the codec AVX2 over-copy needs >=32 B
  slack (documented contract in vaptvupt.h). Old codec never
  reached it; new wider AVX2 hot path does. Fixed with shared
  ZUPT_VV_DECODE_SLACK (64 B) guard on both single-threaded
  (zupt_format.c) and parallel (zupt_parallel.c) decode paths.
  Verified: ASAN 24/24 single-threaded + 15/15 multi-threaded;
  bit-flip fuzz 300 trials 0 crashes / 300 clean rejects. F-09
  byte sweep still 0/1827. vv_decoder.c scalar build made
  -Werror clean for aarch64/Termux. New test tests/test_vv_decode
  _slack.sh. Wire format unchanged (v1.6); 3.0.3 archives extract
  byte-exact.
  knownConditionTrueFalse findings closed in varint decoders
  (dead `&& (x&0x80)` AND-branch after preceding terminator-byte
  early-return). -Wconversion / -Wsign-conversion findings closed
  with explicit casts at two sites. Our 9-file non-vendored C now
  compiles clean under the union of strict GCC warnings including
  -Wconversion -Wsign-conversion -Werror. New regression test
  tests/test_static_analysis.sh (7 assertions) wired into make
  check and make test. Behaviour byte-identical; F-09 byte sweep
  still 0/1827 silent accepts. No source crypto changes.
  src/zupt_main.c exceeded C99's 4095-char ISO limit (was 4121).
  Refactored to 5 fprintf sections; -Woverlength-strings added to
  default CFLAGS so future regressions fail the build. Help text
  drift cleanup (stale "zupt" examples → "vaptvupt", stale "LZ77 +
  Huffman" → "VaptVupt LZ + ANS 2.48.5", license attribution).
  New regression test tests/test_help_consistency.sh (10 assertions
  including the F-13 byte-level guard). No source crypto changes;
  audit posture unchanged from v3.0.1.
  gui/LICENSE-GUI rewritten AGPL-3.0-or-later with historical
  correction note). GUI version-string parsing bug fix (the
  v3.0.0 `replace("zupt ", "")` parser matched the wrong substring
  inside the new rename parenthetical, causing garbled window
  titles; fixed with anchored `_VERSION_RE`). New regression test
  tests/test_gui_branding.sh (11 assertions) wired into make check
  and make test. No source crypto changes; audit posture unchanged
  from v3.0.0 (which itself preserved the v2.3.1 baseline).
  Codec upgrade to VaptVupt LZ + ANS 2.48.5 (two libFuzzer-found fixes:
  csz==0 OOB-READ in vv_dstream_decompress_chunk; UBSan-safe pointer
  arithmetic in vv_copy_match). GUI binary-discovery bug fixed with
  liveness-checking _find_vaptvupt + discovery log. Enhanced manpage
  (597 lines). Wire format unchanged at v1.6. Bidirectional v2.x ↔ v3.0.0
  archive compatibility verified. F-09 byte sweep still 0/1827 silent
  accepts; F-06 HMAC fuzz still 0/2000. No new findings, no findings
  reopened. Security posture unchanged.
  (curated 10-suite, 91-assertion subset) for OBS / Debian / RPM `%check`
  sections. openSUSE OBS files rewritten for cabelo
  (`home:cabelo:innovators/zupt`): license corrected MIT → AGPL-3.0-or-later,
  version bumped 1.5.5 → 2.4.8, changelog history preserved. No source
  changes; audit posture unchanged from v2.3.1.

---

## 1. Cryptographic Test Vector Verification

All primitives tested against published reference vectors:

| Primitive | Standard | Vectors | Status |
|-----------|----------|---------|--------|
| SHA-256 | FIPS 180-4 | 3 (empty, "abc", 448-bit) | **PASS** |
| HMAC-SHA256 | RFC 4231 | 2 (TC2: "Jefe", TC3: 20×0xAA) | **PASS** |
| AES-256-CTR | NIST SP 800-38A | 2 (F.5.5 encrypt, F.5.6 decrypt; 4 blocks) | **PASS** |
| SHA3-256 | FIPS 202 | 2 (empty, "abc") | **PASS** |
| SHAKE-128 | FIPS 202 | 1 (empty, 128-bit output) | **PASS** |
| X25519 | RFC 7748 §5.2 | 2 (both test vectors) | **PASS** |
| ML-KEM-768 | FIPS 203 | 2 (5-trial roundtrip + implicit rejection) | **PASS** |
| XXH64 | xxHash spec | 1 (empty string, seed=0) | **PASS** |
| ML-KEM-768 self-test | internal | 1 (NTT consistent-scaling + CBD bounds) | **PASS** |
| **Total** | | **16** | **16/16 PASS** |

## 2. Jasmin Constant-Time Verification

| Function | Purpose | Status |
|----------|---------|--------|
| `zupt_mac_verify_ct` | HMAC comparison | **✅ Linked, CT-proven** |
| `zupt_ct_select_32` | ML-KEM FO select | **✅ Linked, CT-proven** |
| `zupt_fe_cswap` | X25519 conditional swap | **✅ Linked, CT-proven** |
| `zupt_aes256_blk` | AES-256 single-block (AES-NI) | **✅ Linked, CT by hardware** |
| `zupt_aes256_ctr4` | AES-256 4-block pipeline | **✅ Linked, CT by hardware** |

## 3. ACSL Formal Annotations

19 security-critical functions annotated with `requires/ensures/assigns` contracts.
Target: `frama-c -wp -wp-rte -wp-model Typed+Cast`

## 4. Security Hardening

| Feature | Status |
|---------|--------|
| mlock() key protection | **✅ Active** |
| Buffer canaries (keyring) | **✅ Active** |
| Always-decrypt timing mitigation | **✅ Active** |
| AFL++ fuzz harnesses | **✅ Available** (`make fuzz-build`) |

## 5. VaptVupt Codec Tests

| Test | Status |
|------|--------|
| Roundtrip all 3 modes (UF/BAL/EXT) | **PASS** |
| Roundtrip + AES-256 encryption | **PASS** |
| Roundtrip + PQ hybrid encryption | **PASS** |
| Roundtrip + multi-threaded | **PASS** |
| Roundtrip + solid mode | **PASS** |
| Incompressible fallback to store | **PASS** |
| Empty/small input | **PASS** |
| Multi-block (2 MB) | **PASS** |
| **Total** | **11/11 PASS** |

| Suite | Tests | Result | What It Covers |
|-------|-------|--------|----------------|
| Regression | 16 | **16/16 PASS** | All codecs, modes, encryption, edge cases, corruption detection |
| Multi-threaded | 14 | **14/14 PASS** | N=1/2/4/8 threads, large files, 1000 files, MT+encryption |
| Post-quantum | 10 | **10/10 PASS** | Keygen, PQ encrypt/decrypt, wrong key, password compat, PQ+MT, 2MB |
| Quick smoke | 9 | **9/9 PASS** | Normal, solid, encrypted, wrong pw, MT, fast, store, PQ, integrity |
| NIST vectors | 14 | **14/14 PASS** | See table above |
| **Total** | **62** | **62/62 PASS** | |

Reproduction: `make test-all`

---

## 3. Memory Safety

| Tool | Command | Result |
|------|---------|--------|
| AddressSanitizer | `make test-asan` | **Zero errors** |
| UndefinedBehaviorSanitizer | Built with `-fsanitize=address,undefined` | **Zero errors** |
| All code paths tested | Normal + solid + encrypted + PQ + MT | **Clean** |

Reproduction:
```bash
make test-asan
./zupt_asan compress /tmp/t.zupt /path/to/data/
./zupt_asan extract -o /tmp/out/ /tmp/t.zupt
./zupt_asan keygen -o /tmp/k.key
./zupt_asan compress --pq /tmp/pub.key /tmp/pq.zupt /path/to/data/
./zupt_asan extract --pq /tmp/k.key -o /tmp/pqout/ /tmp/pq.zupt
```

---

## 4. Compiler Warning Audit

| Compiler | Flags | Warnings |
|----------|-------|----------|
| GCC 13.x | `-Wall -Wextra -Wpedantic -O2 -std=c11` | **Zero** |
| Clang 18.x | `-Wall -Wextra -Wpedantic -O2 -std=c11` | **Zero** |

---

## 5. Constant-Time Analysis

| Function | Location | CT Method | Jasmin Verified? | Risk Level |
|----------|----------|-----------|-----------------|------------|
| HMAC comparison | `zupt_crypto.c:252` | 4×u64 XOR accumulation | **Yes** — `zupt_mac_verify_ct` linked | **None** (Jasmin proven) |
| ML-KEM FO select | `zupt_mlkem.c:593` | 4×u64 masked select | **Yes** — `zupt_ct_select_32` linked | **None** (Jasmin proven) |
| ML-KEM NTT butterfly | `zupt_mlkem.c` | Montgomery reduction (branchless) | No | Low |
| ML-KEM CBD sampling | `zupt_mlkem.c` | Bitwise operations only | No | Low |
| X25519 fe_cswap | `zupt_x25519.c:95` | Masked XOR swap | No (limb mismatch) | Low (C is branchless) |
| X25519 Montgomery ladder | `zupt_x25519.c:243` | Fixed 255 iterations | No | Low |
| AES-256 encrypt | `zupt_aes256.c:59` | **Table-based S-box** | **No** | **HIGH on shared HW** |
| SHA-256 | `zupt_sha256.c` | Table-based constants | No | Low (not secret-indexed) |
| Keccak-f[1600] | `zupt_keccak.c` | Bitwise XOR/ROT only | No | None |
| Key wipe | `zupt_crypto.c` | `explicit_bzero` / volatile | No | Low |

### Jasmin Assembly Verification

Two functions confirmed active in binary via `nm`:

```
0000000000014ae0 T zupt_mac_verify_ct    ← Jasmin assembly, CT proven
0000000000014b20 T zupt_ct_select_32     ← Jasmin assembly, CT proven
```

Assembly generated by `jasminc 2026.03.0`. Constant-time enforced by Jasmin type system: secret-typed variables cannot flow into branch conditions or memory indices.

### Not Wired (with reason)

| Function | Issue | Fallback |
|----------|-------|----------|
| `zupt_fe_cswap` | Jasmin: 4×u64 limbs, C: 5×u51 — incompatible | C masked XOR (branchless) |
| `zupt_aes256_blk` | Stack offset bug: `rk.[1]` → `[rsp+1]` not `[rsp+16]` | C table-based AES |

---

## 6. Key Material Lifecycle

| Phase | Method | Verified |
|-------|--------|----------|
| Generation | OS CSPRNG: `getrandom(2)` / `/dev/urandom` / `RtlGenRandom` | Hard fail if unavailable |
| Storage | Stack-local arrays (no heap allocation for keys) | ASAN verified |
| Usage | Passed by const pointer to AES-CTR / HMAC | No copies to heap |
| Wipe | `zupt_secure_wipe()`: `explicit_bzero` (glibc 2.25+), `SecureZeroMemory` (Win), volatile fallback | Compiler cannot optimize out |
| Scope exit | Stack frame destroyed | Keys were on stack |

All intermediate buffers in PBKDF2, hybrid KEM, ML-KEM encaps/decaps, and X25519 wiped before return.

---

## 7. Nonce Security

**Scheme:** `per_block_nonce = base_nonce XOR pad_le(block_seq, 8)`

- `base_nonce`: 128-bit random from CSPRNG, generated once per archive.
- `block_seq`: monotonically increasing 0, 1, 2, ... per archive.
- **Uniqueness within archive:** Guaranteed (distinct seq → distinct nonce).
- **Uniqueness across archives:** 2^-128 collision probability per pair (birthday bound on random base).

---

## 8. Encrypt-then-MAC Ordering

| Step | Action | Verified |
|------|--------|----------|
| 1 | Compute HMAC over `nonce ‖ ciphertext` | HMAC input is nonce+ct, not plaintext |
| 2 | Verify HMAC before any decryption | Code path: MAC check → early return if fail → decrypt only on success |
| 3 | Decrypt only authenticated data | No plaintext produced from unauthenticated ciphertext |

**Prevents:** Chosen-ciphertext attacks, padding oracles, ciphertext tampering.

---

## 9. Bugs Found and Fixed (v0.5.1 → v1.5.0)

| Bug | Severity | Version Fixed | Impact |
|-----|----------|---------------|--------|
| Huffman Kraft-inequality violation | Critical | v0.5.1 | Data corruption on specific inputs |
| Heap-buffer-overflow in LZ match finder | Critical | v0.5.1 | Potential code execution |
| `rand()` CSPRNG fallback | Critical | v0.5.1 | Predictable encryption keys |
| ML-KEM `poly_basemul` OOB | Critical | v1.0.0 | Buffer overread in NTT |
| ML-KEM missing `poly_tomont` | Critical | v1.0.0 | Public key in wrong domain |
| ML-KEM inverted FO `cmov` | Critical | v1.0.0 | Always selected rejection key |
| ML-KEM `inv_ntt` wrong table | High | v1.0.0 | NTT roundtrip failure |
| PQ nonce mismatch | High | v1.0.0 | Encrypt/decrypt used different nonces |
| X25519 `AA + a24*E` formula | High | v1.1.0 | Wrong curve, not interoperable |
| Dead `match_cost()` | Low | v1.1.0 | Clang warning |
| `const polyvec` qualifier | Low | v1.1.0 | Pedantic warnings |
| `__int128` pedantic | Low | v1.1.0 | Pedantic warning |

---

## 10. Known Limitations

| Limitation | Impact | Mitigation | Status |
|------------|--------|------------|--------|
| Table-based AES (C fallback) | Cache-timing on shared hardware | Jasmin AES-NI path exists but has offset bug | **Open** — fix `.jazz` source |
| Table-based SHA-256 | Theoretical cache-timing | Not used on secret-indexed data | **Accepted** |
| PBKDF2 not quantum-safe | Quantum password brute-force | Use `--pq` mode | **Documented** |
| No `mlock()` | Keys swappable to disk | Short key lifetime + `zupt_secure_wipe` | **Planned** |
| No fuzzing performed | Undiscovered bugs | AFL++ setup in FUZZING.md | **Planned** |
| No independent audit | Self-assessed only | Open source + Jasmin proofs | **Planned** |
| X25519 Jasmin not linked | C fallback for fe_cswap | C is branchless but compiler-dependent | **Open** — limb mismatch |

---

© 2026 Cristian Cezar Moisés — AGPL-3.0-or-later

---

## v2.2.1 audit pass — 2026-04-27

This pass focused on the production-readiness of the libzuptsdk integration
introduced in v2.2.0 and on adversarial review of the existing code paths
not previously audited.

### Methodology

Two-pass adversarial review:

- **Pass A (read-and-reason):** read each source file, identify invariants,
  ask "what does an attacker control?", "what happens at boundaries?".
- **Pass B (test-driven):** write a failing test that exercises the suspected
  bug, fix it, write a regression test that fails before the fix and passes
  after.

When A and B disagreed, the discrepancy was investigated rather than
papered over.

### Findings (all fixed in v2.2.1)

| # | File:line | Severity | Description |
|---|---|---|---|
| 1 | `zupt_format.c:146` | low | varint reader truncated at 9 bytes |
| 2 | `zupt_format.c:1529..1699` (×6) | medium | unchecked `fwrite` in extract path → silent corruption |
| 3 | `zupt_crypto_sdk.c:90..` | low (defense-in-depth) | `mac_key` aliased to `enc_key` in SDK paths |
| 4 | `zupt_lz.c:33` | high | `size_t` overflow in LZ length decoder |
| 5 | `zupt_format.c:1610,1681` | high | dedup-ref recursion + OOB seek (DoS) |
| 6 | `zupt_format.c:446,883` | low | encrypt failure left partial archive |

The only finding rated as high severity (#4 and #5) are exploitable from a
malicious archive: an attacker who can convince the user to extract their
archive could trigger a process crash. None of the findings allow code
execution or key recovery; the AEAD layer's authentication tag still
prevents arbitrary writes.

### Test coverage after fixes

| Suite | Count | Status |
|---|---|---|
| Native (run_quick.sh) | 9 | ✓ |
| SDK roundtrip (test_sdk.sh) | 11 | ✓ |
| Audit double-validated (test_audit.sh) | 10 | ✓ NEW |
| Inherited from libzuptsdk 2.1.5 | 169 | ✓ |
| Inherited fuzz iterations (ASAN-clean) | 750,000 | ✓ |
| **Total verified test points** | **199 + 750k fuzz** | **✓** |

### Notes for users

If you are using zupt in production:

- v2.2.1 is a recommended upgrade.
- Archives written with v2.2.0 or earlier remain readable; no migration
  needed.
- The high-severity findings (#4, #5) only affect the *extract* path. If
  you only ever extract archives you created yourself, you are not
  affected by them. If you accept third-party archives, upgrade.
- The `--pq-sdk` mode introduced in v2.2.0 was not affected by any of
  these findings; it was introduced clean and remained clean.

---

## 2026-04-27 — v2.2.1 audit pass

Internal code review against an internal audit checklist (AUDIT_PROMPT — superseded by FORMAL_AUDIT_PROMPT.md). Six bugs
identified and fixed in the same release. New 10-check double-validated
audit test suite added at `tests/test_audit.sh`.

### Bugs found and fixed

| # | File:line | Severity | Description |
|---|---|---|---|
| 1 | `src/zupt_format.c:146` | low | uint64 varint truncated to 63 bits |
| 2 | `src/zupt_format.c` (×6) | medium | unchecked `fwrite` returns in extract path |
| 3 | `src/zupt_crypto_sdk.c` | low | `mac_key` was copy of `enc_key`, now KDF-split |
| 4 | `src/zupt_lz.c:33` | high | `lz_read_extra` size_t overflow → OOB copy |
| 5 | `src/zupt_format.c` (×2) | medium | dedup-ref forward offset + recursion accepted |
| 6 | `src/zupt_format.c` (×2) | low | partial archive not removed on encrypt-init fail |

### Test methodology

- **Path A**: code review identifies invariant; a failing test is constructed.
- **Path B**: an independent property-based check exercises the same invariant from a different angle.
- A test passes only when A and B agree. Disagreement is treated as a finding.

10 audit checks across four categories (authenticated archives, format security, format compatibility, robustness). All passing.

### Cumulative test surface (2.2.1)

| Suite | Tests | Status |
|---|---|---|
| `make test` (run_quick) | 9 | ✓ |
| `tests/test_sdk.sh` | 11 | ✓ |
| `tests/test_audit.sh` | 10 | ✓ |
| **zupt total** | **30** | **✓** |
| Inherited libzuptsdk audit | 42 | ✓ |
| Inherited libzuptsdk RFC + roundtrip | 84 | ✓ |
| Inherited libzuptsdk binding contracts | 57 | ✓ |
| Inherited libzuptsdk Wycheproof | 5 | ✓ |
| **Combined zupt + SDK** | **218** | **✓** |
| Mutation-fuzz iters (ASAN/UBSAN) | 750,000 | ✓ |

### Open items (not blockers)

- No external audit yet.
- `make test-asan` not wired into the zupt Makefile (only the SDK Makefile has it).
- The deduplication path is structurally complex and would benefit from
  property-based testing (currently covered by 30 tests, none property-based).

---

## 2026-04-27 — v2.2.2 audit pass

Second internal review against the same audit checklist, focused on format
parser robustness and dedup path correctness.

### Bugs found and fixed (4)

| # | File:line | Severity | Description |
|---|---|---|---|
| 7 | `zupt_format.c:166` | medium | realloc-pair atomicity: UB on partial failure |
| 8 | `zupt_format.c:138` | low | in-memory varint decoder had same 9-byte truncation as file variant |
| 9 | `zupt_format.c:1267` | medium | `encryption_header_off` not bounds-checked before seek |
| 10 | `zupt_format.c:1402` | medium | `index_offset` not bounds-checked before seek |

### New test surface

- 12 dedup property-based checks (`test_dedup_props.sh`) — covers
  byte-exact roundtrip, dedup space savings, 100%-duplicate sets,
  and dedup + PQ encryption interaction.
- 1000 ASAN/UBSAN fuzz iterations (`fuzz_format`) — zero crashes,
  zero memory errors.

### Cumulative test surface (2.2.2)

| Suite | Tests | Status |
|---|---|---|
| run_quick.sh | 9 | ✓ |
| test_sdk.sh | 11 | ✓ |
| test_audit.sh | 10 | ✓ |
| test_dedup_props.sh | 12 | ✓ NEW |
| **zupt total** | **42** | **✓** |
| Format mutation fuzz (ASAN/UBSAN) | 1,000 iters | ✓ NEW |
| Inherited libzuptsdk audit | 42 | ✓ |
| Inherited libzuptsdk RFC + roundtrip | 84 | ✓ |
| Inherited libzuptsdk binding contracts | 57 | ✓ |
| Inherited libzuptsdk Wycheproof | 5 | ✓ |
| Inherited libzuptsdk fuzz | 750,000 iters | ✓ |
| **Combined zupt + SDK** | **260 tests + 751k fuzz** | **✓** |

### CI

GitHub Actions workflow added at `.github/workflows/ci.yml`:
build-and-test, asan-build, fuzz-format, package-deb. Each run
exercises the full test surface plus fuzz under sanitizers and
verifies the .deb installs cleanly.

### Open items

- External audit still pending (cost-bound, not engineering-bound).
- AppImage build via real `appimagetool` not yet automated in CI.
- The fuzz harness uses a single fixed seed archive; corpus
  diversification (different file types, multi-file archives,
  encrypted seeds) would strengthen coverage further.

---

## 2026-04-27 — v2.2.2 formal audit (no version bump)

Formal cryptographic audit pass conducted using methodology in
`FORMAL_AUDIT_PROMPT.md`. Auditor profile: senior cryptographic
engineering (15+ years production crypto). Threat model: government
archives with 30+ year retention, financial institutions under Brazilian
Central Bank Resolução 4.658/2018, healthcare (LGPD-Saúde), defense
(CNSA 2.0 alignment).

### Methodology

- **Path A**: line-by-line manual review with documented preconditions,
  postconditions, invariants, trust boundaries, failure modes.
- **Path B**: independent adversarial test exercising the same invariant.
- Bug confirmed only when both paths agreed.

### Bugs found and fixed (4)

| # | File | Severity | Description |
|---|---|---|---|
| 11 | `zupt_format.c` (×2) | **HIGH** | Zip Slip path traversal in extract — `e->path` to `fopen` without validation |
| 12 | `zupt_format.c` (×2) | **MEDIUM** | symlink-follow on extract output (`fopen "wb"` follows symlinks) |
| 13 | `zupt_format.c:1593` | LOW | `size_t` overflow on solid-extract size cap (32-bit) |
| 14 | `zupt_format.c:parse_index` | LOW | `count * sizeof(entry)` overflow before calloc (32-bit) |

### Cryptographic primitive review (no findings)

Reviewed every public crypto path against:
- FIPS 197 (AES) — key/IV size, counter init, nonce reuse
- FIPS 202 (Keccak/SHA-3) — rate/capacity, no domain confusion
- FIPS 203 (ML-KEM) — parameter set correctness, key sanitization, decap fault resistance
- RFC 5297 (AES-SIV) — nonce-misuse resistance, AD coverage
- RFC 5869 (HKDF) — salt-vs-IKM separation, info domain separation
- RFC 7748 (X25519) — scalar clamping, all-zero output rejection
- RFC 8439 (ChaCha20-Poly1305) — 192-bit XChaCha nonce, AD coverage
- RFC 9106 (Argon2) — m≥64 MiB, t≥3, p≥1, salt≥16B
- RFC 9180 (HPKE) — suite ID, mode binding, encap context

Findings: **none**. All primitives correctly implemented.

### New regression test suite

`tests/test_path_traversal.sh` — 5 property checks covering:
1. Patched archive with `../` entry does not escape parent dir
2. Patched archive with absolute path does not write to `/tmp/owned`
3. Symlink at extract target is not followed (sentinel preserved)
4. Legitimate paths still extract correctly
5. Deep nested safe paths still work

### Cumulative test surface (2.2.2 final)

| Suite | Tests | Status |
|---|---|---|
| run_quick.sh | 9 | ✓ |
| test_sdk.sh | 11 | ✓ |
| test_audit.sh | 10 | ✓ |
| test_dedup_props.sh | 12 | ✓ |
| test_path_traversal.sh | 5 | ✓ NEW |
| **zupt total** | **47** | **✓** |
| Format mutation fuzz (ASAN/UBSAN) | 1,000 iters | ✓ |
| Inherited libzuptsdk audit | 42 | ✓ |
| Inherited libzuptsdk RFC + roundtrip | 84 | ✓ |
| Inherited libzuptsdk binding contracts | 57 | ✓ |
| Inherited libzuptsdk Wycheproof | 5 | ✓ |
| Inherited libzuptsdk fuzz | 750,000 iters | ✓ |
| **Combined zupt + SDK** | **265 tests + 751k fuzz** | **✓** |

### Portability re-verification

Static portability scan: clean.
- No unaligned pointer casts
- No raw `/` separators (uses `ZUPT_PATH_SEP`)
- No `htonl`/`ntohl`/struct casts (LE helpers throughout)
- No POSIX-only headers without `#ifdef _WIN32` guards

GCC + `-Wpedantic` build: clean.
Win32 paths verified via `-D_WIN32 -E` synthetic preprocessing.

### Cumulative bug count across audit sprints

| Sprint | Bugs found | Severity range |
|---|---|---|
| v2.2.1 (first audit) | 6 | low to high |
| v2.2.2 (second audit) | 4 | low to medium |
| v2.2.2 formal | 4 | low to **high** (Zip Slip path traversal) |
| v2.2.2 sprint 4 | 1 | **critical** (silent extract via arg parser) |
| v2.2.2 god-tier audit | 1 | **critical** (block-swap AEAD) |
| **Total** | **16** | **all fixed and regression-tested** |

### Open items

- External independent audit still pending (cost, not engineering)
- Side-channel timing leak testing not performed
- Cross-OS CI (macOS / Windows / FreeBSD runners) not yet wired
- Formal verification beyond Jasmin constant-time primitives (F*, ProVerif)
  not pursued



## 2026-05-01 — v2.2.3 release audit (VaptVupt 2.48.2 integration)

Two independent test passes performed: one on the working tree, a
second on a clean build from the produced source tarball
(`zupt-2.2.3-source.tar.gz`). Both passes identical and clean.

### Surfaces verified

| Surface | Test target | Pass 1 | Pass 2 | Notes |
|---|---|---|---|---|
| Quick suite | `make test` | 9 + 11 + 10 + 12 + 5 + 8 + 6 = 61 OK | 61 OK | All `tests/*.sh` |
| Regression | `tests/regression.sh` | 22/22 | 22/22 | T17 fixed (see CHANGELOG) |
| Threaded | `tests/test_threaded.sh` | 14/14 | 14/14 | MT compress/decompress |
| Post-quantum | `tests/test_pq.sh` | 10/10 | 10/10 | `--pq-sdk` and legacy `--pq` |
| VaptVupt unit | `make test-vv` | 11/11 | 11/11 | All modes + format_v2 |
| NIST vectors | `make test-vectors` | 14/14 | 14/14 | XXH64, SHA-256, ML-KEM (incl. internal self-test), X25519, AES, HMAC |
| ASAN/UBSan | `make test-asan` | clean | clean | plain + password + `--pq-sdk`; levels 1, 5, 9 |
| Format mutation fuzz | `make fuzz-format-run` | 1000 iters, 0 crashes | 1000 iters, 0 crashes | ASAN-instrumented binary as victim |
| License audit | `make audit-licenses` | clean | clean | All SPDX correct (AGPL for Zupt, GPL for VaptVupt) |
| GCC strict warnings | `-Wall -Wextra -Wpedantic` | 0 | 0 | C11 strict |
| Disk backup | `zupt disk backup`/`restore` | byte-exact sha256 | — | 5 MB image, all PATTERN markers preserved |

Cumulative cases passing: **112 across 12 suites**, both passes.

### Defect found and fixed in this release cycle

VaptVupt 2.48.2 + `format_v2 = 1` + `VV_MODE_ULTRA_FAST` produces
output the decoder rejects with `VV_ERR_OVERFLOW`. The combination
is **not in VaptVupt's upstream test matrix**
(`vaptvupt-2.48.2/tests/test_zupt_integration.c` exercises
`format_v2` only with `BALANCED` and `EXTREME`). Caught by Zupt's own
`tests/regression.sh` T17 (VaptVupt all levels) before release.

Workaround in `src/vaptvupt_api.c`: set `opts.format_v2 = 0` for
levels 1–2 (`VV_MODE_ULTRA_FAST`); leave `format_v2 = 1` for levels
3–9. To be reported upstream; once VaptVupt validates the combination
the guard can be lifted.

### Defect found and fixed in this release cycle (build system)

The `STALE_OBJS` arch-safety guard in `Makefile` was comparing the
canonical strings `x86-64` (from `file(1)`) against `x86_64` (from
`$(CC) -dumpmachine`) and treating them as different architectures,
causing every `make` invocation to wipe and rebuild every `.o` file
even on a consistent host. Both sides are now normalised through
`tr -d '_-' | tr [:upper:] [:lower:]` so the comparison succeeds on a
same-arch tree and only fires when the tarball really did include
cross-arch objects.

### Packages produced and verified

All built from the same source tree, then exercised end-to-end
(encrypted compress + extract + sha256 byte-compare) outside the build
host's normal library search path:

| Package | File | Size | Roundtrip |
|---|---|---|---|
| Debian/Ubuntu | `zupt_2.2.3_amd64.deb` | 365 KB | encrypted OK |
| RPM | `zupt-2.2.3-1.x86_64.rpm` | 468 KB | encrypted OK |
| AppImage | `zupt-2.2.3-x86_64.AppImage` | 569 KB | encrypted OK (extracted) |
| AppDir tarball | `zupt-2.2.3-x86_64.AppDir.tar.gz` | 377 KB | encrypted OK |
| Generic Linux | `zupt-2.2.3-linux-x86_64.tar.gz` | 430 KB | encrypted OK |
| Source | `zupt-2.2.3-source.tar.gz` | 736 KB | rebuilt + full suite OK |

All six produce byte-identical output on the test corpus (records.csv
+ 256 KB random binary + hello.txt).
