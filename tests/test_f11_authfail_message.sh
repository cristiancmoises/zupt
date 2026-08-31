#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# F-11 regression test (ZUPT 2.4.2).
#
# F-11: pre-2.4.2 the AIT-fail message said "archive header or footer has
# been tampered with" in both the actual-tamper case AND the wrong-password
# case (because wrong password → wrong mac_key → AIT mismatch). This
# misled users into thinking valid archives were corrupted when they had
# just mistyped a password.
#
# v2.4.2 collapses both cases into the same generic message by default:
#   "Authentication failed (wrong key, wrong password, or tampered archive)"
# and moves the detailed top-MAC wording behind --verbose. Identical
# message for both cases eliminates a verbal probe-oracle. Plaintext-mode
# tamper detection (no key involvement) keeps detailed wording.

set -Eeuo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
ZUPT=${ZUPT_BIN:-$repo_root/zupt}

if [ ! -x "$ZUPT" ]; then
    echo "  ✗ $ZUPT not found — run 'make' first" >&2
    exit 1
fi
version=$("$ZUPT" --version 2>&1)
SDK_ENABLED=0
if grep -Fq 'libvuptsdk=enabled' <<<"$version"; then
    SDK_ENABLED=1
fi

PASS=0
FAIL=0
P() { PASS=$((PASS+1)); echo "  ✓ $1"; }
F() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

capture_expected_failure() {
    local output_name=$1 label=$2 directory=$3 output status
    shift 3
    set +e
    output=$(cd "$directory" && "$@" 2>&1)
    status=$?
    set -e
    if ((status == 0)); then
        F "$label returned success"
    fi
    printf -v "$output_name" '%s' "$output"
}

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR"

echo "F-11 regression: error-message hygiene"

echo "F-11 payload" > input.txt

# Test 1: wrong-password message on the build's default KDF (no --verbose)
"$ZUPT" c -p correct argon.zupt input.txt >/dev/null 2>&1
mkdir out1
capture_expected_failure ERR 'default KDF wrong-pw' out1 \
    "$ZUPT" x -p wrong ../argon.zupt
if echo "$ERR" | grep -q "Authentication failed (wrong key, wrong password, or tampered archive)"; then
    P "default KDF wrong-pw: generic auth-fail message"
else
    F "default KDF wrong-pw: message wrong: '$ERR'"
fi
# Must NOT contain the standalone "header or footer has been tampered with"
if ! echo "$ERR" | grep -q "header or footer has been tampered with"; then
    P "default KDF wrong-pw: no standalone tamper claim"
else
    F "default KDF wrong-pw: still claims archive tampered"
fi
# Must NOT contain the verbose top-MAC line
if ! echo "$ERR" | grep -q "archive-integrity-trailer (top-MAC)"; then
    P "default KDF wrong-pw: no top-MAC technical detail"
else
    F "default KDF wrong-pw: top-MAC leaked without --verbose"
fi

# Test 2: --verbose surfaces the technical detail
mkdir out2
capture_expected_failure ERR_V 'default KDF wrong-pw --verbose' out2 \
    "$ZUPT" x -p wrong --verbose ../argon.zupt
if echo "$ERR_V" | grep -q "top-MAC"; then
    P "default KDF wrong-pw --verbose: top-MAC detail shown"
else
    F "default KDF wrong-pw --verbose: top-MAC missing"
fi
if echo "$ERR_V" | grep -q "Authentication failed (wrong key, wrong password, or tampered archive)"; then
    P "default KDF wrong-pw --verbose: still has the generic line"
else
    F "default KDF wrong-pw --verbose: missing generic line"
fi

# Test 3: PBKDF2 archive same behaviour
"$ZUPT" c -p correct --kdf pbkdf2 pbkdf.zupt input.txt >/dev/null 2>&1
mkdir out3
capture_expected_failure ERR3 'PBKDF2 wrong-pw' out3 \
    "$ZUPT" x -p wrong ../pbkdf.zupt
if echo "$ERR3" | grep -q "Authentication failed (wrong key, wrong password, or tampered archive)"; then
    P "PBKDF2 wrong-pw default: generic auth-fail message"
else
    F "PBKDF2 wrong-pw default: wrong"
fi

# Test 4: actual header tamper on encrypted archive emits the SAME generic
# message — this is the probe-oracle property.
cp argon.zupt tampered.zupt
python3 -c "
b = bytearray(open('tampered.zupt','rb').read())
b[15] ^= 1  # creation_time byte
open('tampered.zupt','wb').write(bytes(b))"
mkdir out4
capture_expected_failure ERR4 'encrypted header tamper' out4 \
    "$ZUPT" x -p correct ../tampered.zupt
if echo "$ERR4" | grep -q "Authentication failed (wrong key, wrong password, or tampered archive)"; then
    P "Actual tamper (encrypted): same generic message — no verbal oracle"
else
    F "Actual tamper (encrypted): message diverges from wrong-pw case"
fi
# Sanity: extract failed
if [ ! -f out4/input.txt ]; then
    P "Actual tamper (encrypted): extract correctly refused"
else
    F "Actual tamper (encrypted): extract succeeded — bug"
fi

# Test 5: plaintext archive tamper keeps detailed wording (no key, no oracle)
"$ZUPT" c plain.zupt input.txt >/dev/null 2>&1
cp plain.zupt ptamp.zupt
python3 -c "
b = bytearray(open('ptamp.zupt','rb').read())
b[10] ^= 1
open('ptamp.zupt','wb').write(bytes(b))"
mkdir out5
capture_expected_failure ERR5 'plaintext header tamper' out5 \
    "$ZUPT" x ../ptamp.zupt
if echo "$ERR5" | grep -q "corrupted or tampered"; then
    P "Plaintext tamper: detailed XXH64-failure message kept"
else
    F "Plaintext tamper: detailed message missing"
fi
if echo "$ERR5" | grep -q "Authentication failed (wrong key"; then
    F "Plaintext tamper: shouldn't say 'wrong key' (no key involved)"
else
    P "Plaintext tamper: doesn't conflate with key-mode wording"
fi

# Test 6: correct password still extracts successfully
mkdir out6
(cd out6 && "$ZUPT" x -p correct ../argon.zupt >/dev/null 2>&1)
if [ -f out6/input.txt ] && diff -q input.txt out6/input.txt >/dev/null 2>&1; then
    P "Correct password: clean extract preserved"
else
    F "Correct password: regression — extract broken"
fi

# Test 7: when enabled, PQ-SDK wrong key triggers the same generic message.
if ((SDK_ENABLED)); then
    "$ZUPT" keygen --sdk -o k.priv >/dev/null 2>&1
    "$ZUPT" keygen --sdk -o other.priv >/dev/null 2>&1
    "$ZUPT" c --pq-sdk k.priv.pub pq.zupt input.txt >/dev/null 2>&1
    mkdir out7
    capture_expected_failure ERR7 'PQ-SDK wrong key' out7 \
        "$ZUPT" x --pq-sdk ../other.priv ../pq.zupt
    if echo "$ERR7" | grep -q "Authentication failed (wrong key, wrong password, or tampered archive)"; then
        P "PQ-SDK wrong-key: generic auth-fail message"
    else
        F "PQ-SDK wrong-key: didn't get generic message: '$ERR7'"
    fi
else
    echo '  SKIP: PQ-SDK wrong-key message needs system libvuptsdk (WITH_SDK=1)'
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  F-11 regression: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
