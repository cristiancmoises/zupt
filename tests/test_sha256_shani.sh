#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# SHA-256 SHA-NI hardware-path test (v3.2.0).
#
# The SHA-NI compression function in src/zupt_sha256_shani.c accelerates
# HMAC-SHA256 (the Encrypt-then-MAC second pass and PBKDF2) on CPUs with
# the Intel SHA Extensions. This test validates:
#
#   1. The 64 SHA-NI round constants are bit-identical to the scalar
#      K[] table in zupt_sha256.c (catches transcription errors — the
#      single most likely bug in a hand-written SHA-NI routine). This
#      check runs on ALL hosts, SHA-NI or not.
#   2. The SHA-NI object compiles cleanly with -msha -mssse3 -msse4.1.
#   3. zupt_cpu gains has_shani and the dispatch is wired (source check).
#   4. On SHA-NI hardware: the SHA-NI path's digests match NIST FIPS
#      180-4 vectors and the scalar path bit-exact (executed by the C
#      test). On non-SHA-NI hosts this step SKIPS — the instructions
#      cannot be executed — but steps 1-3 still gate the build.

set -u
PASS=0; FAIL=0
P() { echo "  ✓ $1"; PASS=$((PASS+1)); }
F() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "SHA-256 SHA-NI hardware path"

# ── 1. Round-constant equivalence (host-independent) ──
python3 - <<'PYEOF'
import re, sys
scalar = open('src/zupt_sha256.c').read()
m = re.search(r'static const uint32_t K\[64\]\s*=\s*\{(.*?)\};', scalar, re.S)
ks = [int(x,16) for x in re.findall(r'0x[0-9a-fA-F]{8}', m.group(1))]
shani = open('src/zupt_sha256_shani.c').read()
pairs = re.findall(r'_mm_set_epi64x\(\(long long\)0x([0-9A-Fa-f]{16})ULL,\s*\(long long\)0x([0-9A-Fa-f]{16})ULL\)', shani)
kpairs = [(hi,lo) for (hi,lo) in pairs if not hi.lower().startswith('0c0d')]
recon = []
for hi, lo in kpairs:
    hi_u = int(hi,16); lo_u = int(lo,16)
    recon += [lo_u & 0xFFFFFFFF, (lo_u>>32)&0xFFFFFFFF, hi_u & 0xFFFFFFFF, (hi_u>>32)&0xFFFFFFFF]
sys.exit(0 if (len(ks)==64 and recon==ks) else 1)
PYEOF
if [ $? -eq 0 ]; then
    P "SHA-NI round constants bit-identical to scalar K[] (64/64)"
else
    F "SHA-NI round constants DIFFER from scalar K[] table"
fi

# ── 2. has_shani wired into CPU detection ──
if grep -q 'has_shani' include/zupt_cpuid.h && grep -q 'has_shani' src/zupt_cpuid.c; then
    P "has_shani present in CPU feature struct + detection"
else
    F "has_shani not wired into zupt_cpuid"
fi

# ── 3. Dispatch wired in zupt_sha256.c ──
if grep -q 'zupt_sha256_transform_shani' src/zupt_sha256.c && grep -q 'zupt_cpu.has_shani' src/zupt_sha256.c; then
    P "SHA-256 update() dispatches to SHA-NI when available"
else
    F "SHA-256 dispatch to SHA-NI not wired"
fi

# ── 4. Compile + execute the C correctness test ──
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "i686" ]; then
    SHANI_CFLAGS="-msha -mssse3 -msse4.1"
else
    SHANI_CFLAGS=""
fi
TMP=$(mktemp -d)
if gcc -Iinclude -Isrc -Wall -Wextra -Werror $SHANI_CFLAGS -O2 -std=c11 \
       tests/test_sha256_shani.c src/zupt_sha256.c src/zupt_sha256_shani.c src/zupt_cpuid.c \
       -o "$TMP/t" 2>"$TMP/cc.log"; then
    P "SHA-NI test compiles clean (-Werror $SHANI_CFLAGS)"
    OUT=$("$TMP/t")
    echo "$OUT" | sed 's/^/    /'
    if echo "$OUT" | grep -q "failed (skipped"; then
        echo "    (host lacks SHA-NI — execution-level checks deferred to SHA-NI hardware)"
    elif echo "$OUT" | grep -qE "SHA-NI: [0-9]+ passed, 0 failed$"; then
        P "SHA-NI path executes correctly (NIST vectors + scalar agreement)"
    else
        F "SHA-NI C test reported failures"
    fi
else
    F "SHA-NI test failed to compile"
    head -10 "$TMP/cc.log" | sed 's/^/    /'
fi
rm -rf "$TMP"

echo ""
echo "  ───────────────────────────────────────"
echo "  SHA-NI hardware path: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
