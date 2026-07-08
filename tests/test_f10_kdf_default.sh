#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# F-10 regression test (Zupt 2.4.1).
#
# F-10: default password-mode KDF flipped from PBKDF2-SHA256 to Argon2id.
# PBKDF2 remains available via --kdf pbkdf2 for compatibility with
# v2.4.0-and-older readers.
#
# Three assertions:
#   1. `zupt c -p PW out.zupt input` writes an enc-header with type byte
#      0x04 (ZUPT_ENC_PW_ARGON2), and the stderr message says Argon2id.
#   2. `zupt c -p PW --kdf pbkdf2 out.zupt input` writes type byte 0x01
#      (ZUPT_ENC_PBKDF2), and the stderr message says PBKDF2.
#   3. Both archive types roundtrip byte-exact via `zupt x -p PW`.
#   4. Wrong password is rejected for both archive types.

set -u

ZUPT="${ZUPT_BIN:-./zupt}"
# Source-only build (WITH_SDK=0) has no libzuptsdk: the SDK-mode paths this
# test exercises are unavailable, so skip cleanly instead of failing.
_sdkck="$(mktemp -d)"
if ! "$ZUPT" keygen --sdk -o "$_sdkck/p" >/dev/null 2>&1; then
    rm -rf "$_sdkck"; echo "  SKIP: built without libzuptsdk (source-only) - SDK-mode test not applicable"; exit 0
fi
rm -rf "$_sdkck"

case "$ZUPT" in
    /*) ;;
    *)  ZUPT="$PWD/$ZUPT" ;;
esac

if [ ! -x "$ZUPT" ]; then
    echo "  ✗ $ZUPT not found — run 'make' first" >&2
    exit 1
fi

PASS=0
FAIL=0
P() { PASS=$((PASS+1)); echo "  ✓ $1"; }
F() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR"

echo "F-10 regression: password-mode KDF default"

# Helper: read the enc_type byte (payload[0] of the enc-header block).
enc_type_of() {
    python3 -c "
import sys
b = open('$1','rb').read()
off = int.from_bytes(b[36:44],'little')
def vread(buf,o):
    v=0;s=0
    while True:
        x=buf[o]; o+=1; v|=(x&0x7f)<<s
        if not (x&0x80): break
        s+=7
    return v,o
v1,p = vread(b, off+7); v2,p2 = vread(b, p)
print(f'{b[p2+8]:02x}')
"
}

echo "secret payload for KDF test" > input.txt

# 1. Default → Argon2id (0x04)
STDERR_DEFAULT=$("$ZUPT" c -p secret default.zupt input.txt 2>&1)
ETYPE=$(enc_type_of default.zupt)
if [ "$ETYPE" = "04" ]; then
    P "default: enc_type = 0x04 (ZUPT_ENC_PW_ARGON2)"
else
    F "default: enc_type = 0x$ETYPE (expected 0x04)"
fi
if echo "$STDERR_DEFAULT" | grep -qi "Argon2id"; then
    P "default: stderr message names Argon2id"
else
    F "default: stderr message doesn't name Argon2id"
fi

# 2. --kdf pbkdf2 → PBKDF2 (0x01)
STDERR_PB=$("$ZUPT" c -p secret --kdf pbkdf2 legacy.zupt input.txt 2>&1)
ETYPE2=$(enc_type_of legacy.zupt)
if [ "$ETYPE2" = "01" ]; then
    P "--kdf pbkdf2: enc_type = 0x01 (ZUPT_ENC_PBKDF2)"
else
    F "--kdf pbkdf2: enc_type = 0x$ETYPE2 (expected 0x01)"
fi
if echo "$STDERR_PB" | grep -qi "PBKDF2"; then
    P "--kdf pbkdf2: stderr message names PBKDF2"
else
    F "--kdf pbkdf2: stderr message doesn't name PBKDF2"
fi

# 3. Roundtrips
mkdir out_a && (cd out_a && "$ZUPT" x -p secret ../default.zupt >/dev/null 2>&1)
if [ -f out_a/input.txt ] && diff -q input.txt out_a/input.txt >/dev/null 2>&1; then
    P "Argon2id archive roundtrips byte-exact"
else
    F "Argon2id roundtrip"
fi

mkdir out_p && (cd out_p && "$ZUPT" x -p secret ../legacy.zupt >/dev/null 2>&1)
if [ -f out_p/input.txt ] && diff -q input.txt out_p/input.txt >/dev/null 2>&1; then
    P "PBKDF2 archive roundtrips byte-exact"
else
    F "PBKDF2 roundtrip"
fi

# 4. Wrong password rejected (both)
mkdir out_wa && (cd out_wa && "$ZUPT" x -p wrong ../default.zupt >/dev/null 2>&1)
if [ ! -f out_wa/input.txt ]; then
    P "Argon2id: wrong password rejected"
else
    F "Argon2id: wrong password accepted"
fi
mkdir out_wp && (cd out_wp && "$ZUPT" x -p wrong ../legacy.zupt >/dev/null 2>&1)
if [ ! -f out_wp/input.txt ]; then
    P "PBKDF2: wrong password rejected"
else
    F "PBKDF2: wrong password accepted"
fi

# 5. --kdf argon2id (explicit form) → same as default
STDERR_E=$("$ZUPT" c -p secret --kdf argon2id explicit.zupt input.txt 2>&1)
ETYPE3=$(enc_type_of explicit.zupt)
if [ "$ETYPE3" = "04" ]; then
    P "--kdf argon2id (explicit): enc_type = 0x04"
else
    F "--kdf argon2id (explicit): enc_type = 0x$ETYPE3"
fi

# 6. --kdf garbage → reject
if "$ZUPT" c -p secret --kdf garbage garbage.zupt input.txt >/dev/null 2>&1; then
    F "--kdf garbage was accepted (should reject)"
else
    P "--kdf garbage rejected"
fi

echo ""
echo "  ───────────────────────────────────────"
echo "  F-10 regression: $PASS passed, $FAIL failed"
echo "  ───────────────────────────────────────"
[ "$FAIL" = 0 ] || exit 1
