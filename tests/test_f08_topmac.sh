#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# F-08 regression test (Zupt 2.3.0).
#
# Two directions:
#   1. v1.5 archive: tamper at each previously-cosmetic header/footer byte
#      MUST be detected (top-MAC verifies header+footer[0..23]).
#   2. v1.4 archive (built by Zupt 2.2.5 binary, embedded as a fixture):
#      MUST extract cleanly with the legacy-downgrade warning on stderr.
#
# The v1.4 fixture is built at test time IF a 2.2.5 binary is available
# under tests/fixtures/, else direction #2 is skipped with a NOTE.

set -u

PASS=0
FAIL=0
ZUPT="${ZUPT_BIN:-./zupt}"
# Resolve to absolute path so the test continues to find the binary after cd.
case "$ZUPT" in
    /*) ;;
    *)  ZUPT="$PWD/$ZUPT" ;;
esac
ROOT="$PWD"

P() { PASS=$((PASS+1)); echo "  ✓ $1"; }
F() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

if [ ! -x "$ZUPT" ]; then
    echo "  ✗ $ZUPT not found — run 'make' first" >&2
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

cd "$TMPDIR"

echo "  [Direction 1: v1.5 archive detects header+footer tamper]"

"$ZUPT" keygen --sdk -o k.priv >/dev/null 2>&1
echo "data" > input.txt
"$ZUPT" c --pq-sdk k.priv.pub a.zupt input.txt >/dev/null 2>&1

SZ=$(wc -c < a.zupt)
if [ "$SZ" -lt 100 ]; then F "couldn't build v1.5 archive"; exit 1; fi

# Sanity: untouched archive extracts.
mkdir -p clean
( cd clean && "$ZUPT" x --pq-sdk ../k.priv ../a.zupt >/dev/null 2>&1 )
if [ -f clean/input.txt ]; then P "clean v1.5 archive extracts"; else F "clean v1.5 archive extract"; fi

# Confirm any v1.5+ archive with top-MAC HMAC-SHA256 is reported.
# (The original write path made v1.5; from 2.3.1 onwards it's v1.6+. The
# test only cares that the AIT is present and reported.)
INFO=$("$ZUPT" info a.zupt 2>&1)
if echo "$INFO" | grep -qE "Format: *v1\.(5|6|7|8|9)" && echo "$INFO" | grep -q "Top-MAC: *YES (HMAC-SHA256)"; then
    P "zupt info reports v1.5+ / Top-MAC HMAC-SHA256"
else
    F "zupt info v1.5+ report"
fi

# Tamper at each header byte (0..63) and each footer byte (SZ-64..SZ-33).
TAMPER_POSITIONS="8 9 10 11 12 14 16 20 24 28 32 36 40 44 48 52 56 60"
FOOTER_START=$((SZ - 64))
for f in 0 4 8 12 16 20 23; do
    TAMPER_POSITIONS="$TAMPER_POSITIONS $((FOOTER_START + f))"
done

ALL_DETECTED=1
for POS in $TAMPER_POSITIONS; do
    cp a.zupt t.zupt
    python3 -c "
b=bytearray(open('t.zupt','rb').read())
b[$POS] ^= 1
open('t.zupt','wb').write(bytes(b))"
    rm -rf out && mkdir out
    ( cd out && "$ZUPT" x --pq-sdk ../k.priv ../t.zupt >/dev/null 2>&1 )
    if [ -f out/input.txt ]; then
        ALL_DETECTED=0
        echo "    silent-accepted tamper at byte $POS"
    fi
done
if [ "$ALL_DETECTED" = 1 ]; then
    P "all 25 header+footer tamper positions rejected"
else
    F "some header+footer tampers silently accepted"
fi

# Also: tamper SHOULD trigger a clear error message. Post-F-11 (v2.4.2)
# the default message is generic ("Authentication failed (wrong key,
# wrong password, or tampered archive)") to avoid a verbal probe-oracle;
# the technical "top-MAC" wording is only shown with --verbose. The F-08
# assertion is that the user is *informed* and the extract is refused —
# either wording satisfies that.
cp a.zupt t.zupt
python3 -c "
b=bytearray(open('t.zupt','rb').read())
b[20] ^= 1  # archive_id byte
open('t.zupt','wb').write(bytes(b))"
rm -rf out && mkdir out
ERR=$( cd out && "$ZUPT" x --pq-sdk ../k.priv ../t.zupt 2>&1 || true )
if echo "$ERR" | grep -qE "Authentication failed|top-MAC"; then
    P "tamper produces a clear auth/integrity error"
else
    F "tamper error message ambiguous: $ERR"
fi

# Verbose mode: top-MAC wording must still surface for debugging
rm -rf out && mkdir out
ERR_V=$( cd out && "$ZUPT" x --verbose --pq-sdk ../k.priv ../t.zupt 2>&1 || true )
if echo "$ERR_V" | grep -q "top-MAC"; then
    P "tamper with --verbose surfaces top-MAC detail"
else
    F "tamper --verbose did not surface top-MAC: $ERR_V"
fi

echo ""
echo "  [Direction 2: v1.4 backward-compat]"

FIXTURE_BIN="$ROOT/tests/fixtures/zupt-2.2.5"
if [ -x "$FIXTURE_BIN" ]; then
    # Build v1.4 archive using the 2.2.5 binary.
    "$FIXTURE_BIN" keygen --sdk -o k14.priv >/dev/null 2>&1
    "$FIXTURE_BIN" c --pq-sdk k14.priv.pub a14.zupt input.txt >/dev/null 2>&1

    # v2.3.0 info should say v1.4 / no top-MAC.
    INFO14=$("$ZUPT" info a14.zupt 2>&1)
    if echo "$INFO14" | grep -q "Format: *v1.4" && echo "$INFO14" | grep -q "Top-MAC: *no"; then
        P "v1.4 archive reported as v1.4 / no top-MAC"
    else
        F "v1.4 info report wrong"
    fi

    # v2.3.0 extract should succeed with warning.
    mkdir out14
    OUT=$( cd out14 && "$ZUPT" x --pq-sdk ../k14.priv ../a14.zupt 2>&1 )
    if [ -f out14/input.txt ] && echo "$OUT" | grep -qi "legacy v1.4 archive"; then
        P "v1.4 archive extracts with legacy warning"
    else
        F "v1.4 backward-compat broken: $OUT"
    fi
else
    echo "  NOTE: tests/fixtures/zupt-2.2.5 not present — direction 2 skipped"
    echo "        (build it once with: cd tests/fixtures && tar xzf zupt-2.2.5.tar.gz"
    echo "         && cd zupt-2.2.5 && make && cp zupt ../zupt-2.2.5)"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  F-08 regression: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
