#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Cristian Cezar Moisés
#
# Exact-content_size decode OOB regression (codec 2.60.4 fix) under ASan,
# plus a tool-level BCJ roundtrip on a real binary fixture at the levels
# where the auto-filter engages. Codec sources are compiled directly with
# -fsanitize=address (never link sanitized objects against the project's
# non-sanitized .o files — ASan static-archive poisoning).

set -u
ARCH=$(uname -m)
SIMD=""
if [[ $ARCH == x86_64 ]] && grep -qiw avx2 /proc/cpuinfo 2>/dev/null; then
    SIMD="-mavx2"
else
    echo "  SKIP: AVX2-specific subpath unavailable; scalar exact-size test remains enabled"
fi

TMP=$(mktemp -d)
rc=0

echo "Codec exact-size + BCJ roundtrip"

if gcc -Iinclude -Wall -Wextra -Werror -O1 -g -std=c11 -fsanitize=address $SIMD \
       tests/test_codec_exact_size.c \
       src/vaptvupt_api.c src/vv_ans.c src/vv_bcj.c src/vv_decoder.c \
       src/vv_encoder.c src/vv_huffman.c src/vv_simd.c src/vv_xxh64.c \
       -o "$TMP/t" 2>"$TMP/cc.log"; then
    "$TMP/t"; rc=$?
else
    echo "  ✗ exact-size test failed to compile"; head -12 "$TMP/cc.log" | sed 's/^/    /'; rc=1
fi

# Tool-level BCJ roundtrip: real binary fixture at L5 (BALANCED+auto-filter)
# and L9 (EXTREME+auto-filter); byte-exact extraction required. Guards the
# F-16 defect class (old in-tree BCJ wrote undecodable streams).
FX=${ZUPT_BIN:-./zupt}
if [ -f "$FX" ] && [ -x ./zupt ]; then
    for L in 5 9; do
        rm -rf "$TMP/o$L"; mkdir -p "$TMP/o$L"
        ./zupt c -l $L "$TMP/a$L.zupt" "$FX" >/dev/null 2>&1
        ./zupt x -o "$TMP/o$L" "$TMP/a$L.zupt" >/dev/null 2>&1
        F=$(find "$TMP/o$L" -type f | head -1)
        if [ -n "$F" ] && diff -q "$F" "$FX" >/dev/null 2>&1; then
            echo "  ✓ BCJ roundtrip L$L (binary fixture) byte-exact"
        else
            echo "  ✗ BCJ roundtrip L$L FAILED"; rc=1
        fi
    done
else
    echo "  - BCJ tool roundtrip skipped (source-built executable missing)"
fi

rm -rf "$TMP"
exit $rc
