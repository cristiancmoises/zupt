#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# Builds and runs the incremental HMAC-SHA256 equivalence test (v3.3.0).
# The per-block MAC path streams segments through an incremental HMAC
# instead of concatenating into a malloc'd buffer; this pins the
# byte-equivalence that wire-format compatibility depends on.

set -u
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "i686" ]; then
    SHANI="-msha -mssse3 -msse4.1"
else
    SHANI=""
fi

TMP=$(mktemp -d)
if gcc -Iinclude -Isrc -Wall -Wextra -Werror $SHANI -O2 -std=c11 \
       tests/test_hmac_incremental.c \
       src/zupt_sha256.c src/zupt_sha256_shani.c src/zupt_crypto.c \
       src/zupt_aes256.c src/zupt_xxh.c src/zupt_keccak.c \
       src/zupt_x25519.c src/zupt_mlkem.c src/zupt_cpuid.c src/zupt_mlock.c \
       -o "$TMP/t" -lm 2>"$TMP/cc.log"; then
    "$TMP/t"; rc=$?
else
    echo "  ✗ incremental-HMAC test failed to compile"
    head -15 "$TMP/cc.log" | sed 's/^/    /'
    rc=1
fi
rm -rf "$TMP"
exit $rc
