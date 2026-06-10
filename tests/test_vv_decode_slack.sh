#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Regression test for the VaptVupt AVX2 decode over-copy guard.
#
# History (codec 2.48.5 -> 2.53.3 integration, sprint 3.1.0):
#   The VaptVupt codec's AVX2 decode hot path (match_copy_32_hot ->
#   _mm256_storeu_si256) over-writes up to 32 bytes past the logical
#   output end. vaptvupt.h documents this: "may over-read/write by up
#   to 32 bytes. Caller must ensure sufficient slack in destination."
#   Our decode buffers were malloc(uncompressed_size) with NO slack.
#   Codec 2.48.5 never reached it on real inputs; 2.53.3's wider AVX2
#   hot path does (ASAN: heap-buffer-overflow WRITE of size 32, 0 bytes
#   after a 128 KB block buffer, on degenerate all-repeats input at L1).
#
#   Fix: over-allocate every decode buffer by ZUPT_VV_DECODE_SLACK (64 B)
#   and pass the padded capacity to the codec. Both decode paths
#   (zupt_format.c single-threaded, zupt_parallel.c multi-threaded).
#
# This test asserts the guard is present and that the exact ASAN-failing
# input round-trips clean.

set -u
PASS=0; FAIL=0
P() { echo "  ✓ $1"; PASS=$((PASS+1)); }
F() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

BIN=./vaptvupt
[ -x ./vaptvupt ] || BIN=./zupt
[ -x "$BIN" ] || { echo "ERROR: no built binary"; exit 2; }

echo "VaptVupt decode over-copy guard"

# ── Source-level guards ──
# The shared constant must exist in zupt.h.
if grep -qE '#define\s+ZUPT_VV_DECODE_SLACK\s+[0-9]+' include/zupt.h; then
    SLACK=$(grep -E '#define\s+ZUPT_VV_DECODE_SLACK' include/zupt.h | grep -oE '[0-9]+')
    if [ "$SLACK" -ge 32 ]; then
        P "ZUPT_VV_DECODE_SLACK defined in zupt.h and >= 32 (is $SLACK)"
    else
        F "ZUPT_VV_DECODE_SLACK is $SLACK — must be >= 32 (AVX2 over-copy width)"
    fi
else
    F "ZUPT_VV_DECODE_SLACK missing from zupt.h"
fi

# Single-threaded decode path must allocate with the slack.
if grep -qE 'malloc\(\*olen \+ ZUPT_VV_DECODE_SLACK\)' src/zupt_format.c; then
    P "zupt_format.c decode buffer is over-allocated by the slack"
else
    F "zupt_format.c decode buffer NOT over-allocated (regression)"
fi
# ...and pass the padded capacity to the codec.
if grep -qE '\*olen \+ ZUPT_VV_DECODE_SLACK' src/zupt_format.c; then
    P "zupt_format.c passes padded capacity to vvz_decompress"
else
    F "zupt_format.c does not pass padded capacity"
fi

# Parallel decode path must do the same.
if grep -qE 'malloc\(olen \+ ZUPT_VV_DECODE_SLACK\)' src/zupt_parallel.c; then
    P "zupt_parallel.c decode buffer is over-allocated by the slack"
else
    F "zupt_parallel.c decode buffer NOT over-allocated (regression)"
fi
if grep -qE 'olen \+ ZUPT_VV_DECODE_SLACK' src/zupt_parallel.c; then
    P "zupt_parallel.c passes padded capacity to vv_decompress"
else
    F "zupt_parallel.c does not pass padded capacity"
fi

# ── Functional: the exact ASAN-failing input round-trips ──
# Degenerate all-repeats: one 4.5 KB pattern repeated to 10 MB, the
# input class that triggered the original over-write at L1.
WORK=$(mktemp -d)
python3 -c "
pat = (b'The quick brown fox jumps over the lazy dog. ' * 100)
data = (pat * (10*1024*1024 // len(pat) + 1))[:10*1024*1024]
open('$WORK/redundant.dat','wb').write(data)
"
SLACK_OK=1
for L in 1 5 9; do
    "$BIN" c -l $L "$WORK/a.zupt" "$WORK/redundant.dat" >/dev/null 2>&1
    rm -rf "$WORK/out"; mkdir -p "$WORK/out"
    "$BIN" x -o "$WORK/out" "$WORK/a.zupt" >/dev/null 2>&1
    ex=$(find "$WORK/out" -type f | head -1)
    if [ -z "$ex" ] || ! diff -q "$ex" "$WORK/redundant.dat" >/dev/null 2>&1; then
        SLACK_OK=0; F "degenerate-input L$L round-trip mismatch"
    fi
done
[ "$SLACK_OK" = 1 ] && P "degenerate all-repeats round-trips byte-exact (L1/5/9)"

# Multi-threaded variant (exercises zupt_parallel.c decode).
MT_OK=1
for L in 1 9; do
    "$BIN" c -l $L -t 4 "$WORK/mt.zupt" "$WORK/redundant.dat" >/dev/null 2>&1
    rm -rf "$WORK/mtout"; mkdir -p "$WORK/mtout"
    "$BIN" x -t 4 -o "$WORK/mtout" "$WORK/mt.zupt" >/dev/null 2>&1
    ex=$(find "$WORK/mtout" -type f | head -1)
    if [ -z "$ex" ] || ! diff -q "$ex" "$WORK/redundant.dat" >/dev/null 2>&1; then
        MT_OK=0; F "degenerate-input L$L (MT) round-trip mismatch"
    fi
done
[ "$MT_OK" = 1 ] && P "degenerate all-repeats round-trips byte-exact (MT, L1/9)"

rm -rf "$WORK"

echo ""
echo "  ───────────────────────────────────────"
echo "  Decode over-copy guard: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
