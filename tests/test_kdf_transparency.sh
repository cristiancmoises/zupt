#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés
#
# F-15 — Argon2id KDF parameter transparency (v3.4.0).
# Builds and runs tests/test_kdf_transparency.c against the vendored SDK.

set -u
SDK_DIR="${ZUPTSDK_DIR:-vendor/zuptsdk}"
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "i686" ]; then
    SHANI="-msha -mssse3 -msse4.1"
else
    SHANI=""
fi

TMP=$(mktemp -d)
if gcc -Iinclude -Isrc -I"$SDK_DIR/include" -Wall -Wextra -Werror $SHANI -O2 -std=c11 \
       tests/test_kdf_transparency.c \
       src/zupt_crypto_sdk.c src/zupt_crypto.c src/zupt_sha256.c src/zupt_sha256_shani.c \
       src/zupt_aes256.c src/zupt_xxh.c src/zupt_keccak.c src/zupt_x25519.c \
       src/zupt_mlkem.c src/zupt_cpuid.c src/zupt_mlock.c \
       -L"$SDK_DIR" -lzuptsdk -Wl,-rpath,"$(cd "$SDK_DIR" && pwd)" -lm \
       -o "$TMP/t" 2>"$TMP/cc.log"; then
    "$TMP/t"; rc=$?
else
    echo "  ✗ KDF-transparency test failed to compile"
    head -15 "$TMP/cc.log" | sed 's/^/    /'
    rc=1
fi
rm -rf "$TMP"
exit $rc
