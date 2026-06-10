#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# F-09 regression test (Zupt 2.3.1).
#
# F-09 closed the per-block frame preface tamper window by:
#   1. Binding the canonical preface (block_type, codec_id, block_flags,
#      sizes, plaintext-XXH64) into the per-block HMAC via the new v1.6
#      ZUPT_FLAG_AAD_PREFACE policy.
#   2. Adding strict structural validation of the encryption-header
#      block's frame preface in read_enc_header (same pattern as F-07
#      for the index block in v2.2.5).
#
# This test does the full exhaustive byte sweep on a small v1.6 PQ-SDK
# archive: every byte from 0 to N-1 is flipped one at a time, and we
# assert the extract fails for ALL of them. With pre-F-09 code this
# would show 15-18 silent acceptances; post-F-09 it must show zero.
#
# Why limit to PQ-SDK encrypted: plaintext archives have no HMAC at
# all (XXH64 best-effort only), so per-byte coverage is intentionally
# weaker and a different, separately-tracked promise.

set -u

ZUPT="${ZUPT_BIN:-./zupt}"
case "$ZUPT" in
    /*) ;;
    *)  ZUPT="$PWD/$ZUPT" ;;
esac

if [ ! -x "$ZUPT" ]; then
    echo "  ✗ $ZUPT not found — run 'make' first" >&2
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR"

"$ZUPT" keygen --sdk -o k.priv >/dev/null 2>&1
echo "F-09 regression test payload" > input.txt
"$ZUPT" c --pq-sdk k.priv.pub a.zupt input.txt >/dev/null 2>&1

SZ=$(wc -c < a.zupt)
if [ "$SZ" -lt 100 ] || [ "$SZ" -gt 10000 ]; then
    echo "  ✗ unexpected archive size $SZ" >&2
    exit 1
fi

# Sanity: clean archive extracts.
mkdir -p clean
( cd clean && "$ZUPT" x --pq-sdk ../k.priv ../a.zupt >/dev/null 2>&1 )
if [ ! -f clean/input.txt ]; then
    echo "  ✗ clean v1.6 PQ-SDK archive doesn't extract" >&2
    exit 1
fi

# Exhaustive sweep.
echo "  [F-09: exhaustive byte sweep of $SZ-byte v1.6 PQ-SDK archive]"
UNDETECTED_POSITIONS=""
TAMPER_SAMPLED=0
for POS in $(seq 0 $((SZ - 1))); do
    cp a.zupt t.zupt
    python3 -c "
b=bytearray(open('t.zupt','rb').read())
b[$POS] ^= 1
open('t.zupt','wb').write(bytes(b))"
    rm -rf out && mkdir out
    ( cd out && "$ZUPT" x --pq-sdk ../k.priv ../t.zupt >/dev/null 2>&1 )
    TAMPER_SAMPLED=$((TAMPER_SAMPLED + 1))
    if [ -f out/input.txt ]; then
        UNDETECTED_POSITIONS="$UNDETECTED_POSITIONS $POS"
    fi
done

UNDETECTED_COUNT=$(echo $UNDETECTED_POSITIONS | wc -w)

echo ""
echo "  ───────────────────────────────────────"
if [ "$UNDETECTED_COUNT" = 0 ]; then
    echo "  F-09 regression: $TAMPER_SAMPLED tamper positions tested, 0 silent-accepted ✓"
    echo "  ───────────────────────────────────────"
    exit 0
else
    echo "  F-09 regression: $UNDETECTED_COUNT silent-accepted positions (must be 0)"
    echo "  positions:$UNDETECTED_POSITIONS"
    echo "  ───────────────────────────────────────"
    exit 1
fi
