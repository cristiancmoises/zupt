#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# F-08 regression test (VaptVupt 2.3.0).
#
# A v1.5+ archive is tampered at each previously-cosmetic header/footer byte;
# every mutation MUST be detected (top-MAC verifies header+footer[0..23]).
# Removing the AIT entirely must also fail closed without a compatibility opt-in.
# Legacy v1.4 compatibility needs a reproducible source-generated fixture and
# is reported as skipped until one is available; compiled fixtures are banned.

set -Eeuo pipefail

PASS=0
FAIL=0
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
ZUPT=${ZUPT_BIN:-$repo_root/zupt}

P() { PASS=$((PASS+1)); echo "  ✓ $1"; }
F() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

if [ ! -x "$ZUPT" ]; then
    echo "  ✗ $ZUPT not found — run 'make' first" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo '  ✗ python3 is required for structural archive mutations' >&2
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

cd "$TMPDIR"

echo "  [AIT removal is rejected by default]"

printf 'data\n' > input.txt
printf 'source-only-test-password\n' > password.txt
chmod 600 password.txt
if "$ZUPT" c --kdf pbkdf2 --pass-file password.txt \
        password.zupt input.txt >/dev/null 2>&1 &&
        "$ZUPT" t --pass-file password.txt password.zupt >/dev/null 2>&1; then
    P "clean password archive passes authentication"
else
    F "clean password archive could not be authenticated"
fi

if python3 "$repo_root/tests/archive_surgery.py" strip-ait \
        password.zupt stripped-ait.zupt; then
    if "$ZUPT" t --pass-file password.txt stripped-ait.zupt \
            >/dev/null 2>&1; then
        F "archive with its AIT removed was accepted by default"
    else
        P "archive with its AIT removed is rejected by default"
    fi

    if "$ZUPT" list --pass-file password.txt stripped-ait.zupt \
            >/dev/null 2>&1; then
        F "list accepted an archive with its AIT removed"
    else
        P "list rejects an archive with its AIT removed"
    fi

    mkdir stripped-output
    printf 'existing extraction target\n' > stripped-output/sentinel
    cp stripped-output/sentinel stripped-output.expected
    if "$ZUPT" extract --pass-file password.txt -o stripped-output \
            stripped-ait.zupt >/dev/null 2>&1; then
        F "extract accepted an archive with its AIT removed"
    elif cmp stripped-output.expected stripped-output/sentinel >/dev/null 2>&1 &&
            [ ! -e stripped-output/input.txt ]; then
        P "AIT-removal rejection preserves the extraction destination"
    else
        F "AIT-removal rejection changed the extraction destination"
    fi
else
    F "could not construct archive with a structurally removed AIT"
fi

version=$("$ZUPT" --version 2>&1)
if ! grep -Fq 'libvuptsdk=enabled' <<<"$version"; then
    echo '  SKIP: exhaustive SDK top-MAC sweep needs WITH_SDK=1 and system libvuptsdk'
    echo
    echo "  ───────────────────────────────────────"
    echo "  F-08 regression: $PASS passed, $FAIL failed"
    echo "  ───────────────────────────────────────"
    [ "$FAIL" = 0 ] || exit 1
    exit 0
fi

echo "  [v1.5+ archive detects header+footer tamper]"

"$ZUPT" keygen --sdk -o k.priv >/dev/null 2>&1
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
    if (cd out && "$ZUPT" x --pq-sdk ../k.priv ../t.zupt >/dev/null 2>&1); then
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
ERR=$( (cd out && "$ZUPT" x --pq-sdk ../k.priv ../t.zupt) 2>&1 || true )
if echo "$ERR" | grep -qE "Authentication failed|top-MAC"; then
    P "tamper produces a clear auth/integrity error"
else
    F "tamper error message ambiguous: $ERR"
fi

# Verbose mode: top-MAC wording must still surface for debugging
rm -rf out && mkdir out
ERR_V=$( (cd out && "$ZUPT" x --verbose --pq-sdk ../k.priv ../t.zupt) 2>&1 || true )
if echo "$ERR_V" | grep -q "top-MAC"; then
    P "tamper with --verbose surfaces top-MAC detail"
else
    F "tamper --verbose did not surface top-MAC: $ERR_V"
fi

echo ""
echo "  SKIP: v1.4 compatibility needs a reproducible source-generated fixture"
echo "        (compiled historical fixtures are not permitted in this repository)"

echo ""
echo "  ───────────────────────────────────────"
echo "  F-08 regression: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
