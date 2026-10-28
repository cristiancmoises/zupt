#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025-2026 Cristian Cezar Moisés

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
CC=${CC:-cc}
MAKE=${MAKE:-make}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

mkdir -p "$TMP/include"

cat >"$TMP/include/zuptsdk.h" <<'EOF'
#ifndef TEST_ZUPTSDK_H
#define TEST_ZUPTSDK_H

#include <stddef.h>
#include <stdint.h>

typedef struct zuptsdk_ctx zuptsdk_ctx_t;
typedef struct zuptsdk_keypair zuptsdk_keypair_t;

int zuptsdk_ctx_create(zuptsdk_ctx_t **ctx_out);
void zuptsdk_ctx_destroy(zuptsdk_ctx_t *ctx);
int zuptsdk_keypair_generate(zuptsdk_ctx_t *ctx, zuptsdk_keypair_t **kp_out);
void zuptsdk_keypair_destroy(zuptsdk_keypair_t *kp);
int zuptsdk_keypair_save_private(const zuptsdk_keypair_t *kp, const char *path);
int zuptsdk_keypair_save_public(const zuptsdk_keypair_t *kp, const char *path);
void zuptsdk_free(void *ptr);
void zuptsdk_secure_zero(void *buf, size_t bytes);

#endif
EOF

cat >"$TMP/include/zuptsdk_easy.h" <<'EOF'
#ifndef TEST_ZUPTSDK_EASY_H
#define TEST_ZUPTSDK_EASY_H

#include "zuptsdk.h"

int zuptsdk_easy_encrypt(const char *recipient_pubkey_path,
                         const uint8_t *plaintext, size_t plaintext_sz,
                         uint8_t **blob_out, size_t *blob_sz);
int zuptsdk_easy_decrypt(const char *recipient_privkey_path,
                         const uint8_t *blob, size_t blob_sz,
                         uint8_t **plaintext_out, size_t *plaintext_sz);
int zuptsdk_easy_derive_key(const char *password,
                            const uint8_t salt[16], uint8_t key_out[32]);
int zuptsdk_easy_random_salt(uint8_t out[16]);

#endif
EOF

cat >"$TMP/fake_sdk.c" <<'EOF'
#include "zuptsdk_easy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int zuptsdk_ctx_create(zuptsdk_ctx_t **ctx_out) {
    if (ctx_out) *ctx_out = NULL;
    return -1;
}

void zuptsdk_ctx_destroy(zuptsdk_ctx_t *ctx) { (void)ctx; }

int zuptsdk_keypair_generate(zuptsdk_ctx_t *ctx, zuptsdk_keypair_t **kp_out) {
    (void)ctx;
    if (kp_out) *kp_out = NULL;
    return -1;
}

void zuptsdk_keypair_destroy(zuptsdk_keypair_t *kp) { (void)kp; }

int zuptsdk_keypair_save_private(const zuptsdk_keypair_t *kp,
                                const char *path) {
    (void)kp;
    (void)path;
    return -1;
}

int zuptsdk_keypair_save_public(const zuptsdk_keypair_t *kp,
                               const char *path) {
    (void)kp;
    (void)path;
    return -1;
}

void zuptsdk_free(void *ptr) { free(ptr); }

void zuptsdk_secure_zero(void *buf, size_t bytes) {
    if (buf) memset(buf, 0, bytes);
}

int zuptsdk_easy_encrypt(const char *recipient_pubkey_path,
                         const uint8_t *plaintext, size_t plaintext_sz,
                         uint8_t **blob_out, size_t *blob_sz) {
    (void)recipient_pubkey_path;
    (void)plaintext;
    (void)plaintext_sz;
    if (blob_out) *blob_out = NULL;
    if (blob_sz) *blob_sz = 0;
    return -1;
}

int zuptsdk_easy_decrypt(const char *recipient_privkey_path,
                         const uint8_t *blob, size_t blob_sz,
                         uint8_t **plaintext_out, size_t *plaintext_sz) {
    (void)recipient_privkey_path;
    (void)blob;
    (void)blob_sz;
    if (plaintext_out) *plaintext_out = NULL;
    if (plaintext_sz) *plaintext_sz = 0;
    return -1;
}

int zuptsdk_easy_random_salt(uint8_t out[16]) {
    if (!out) return -1;
    memset(out, 0x42, 16);
    return 0;
}

int zuptsdk_easy_derive_key(const char *password, const uint8_t salt[16],
                            uint8_t key_out[32]) {
    const char *trace = getenv("ZUPT_TEST_SDK_TRACE");
    clock_t start, now;
    FILE *stream;
    size_t password_len;

    if (!password || !salt || !key_out || !trace) return -1;
    password_len = strlen(password);
    if (password_len == 0) return -1;
    for (size_t i = 0; i < 32; ++i)
        key_out[i] = (uint8_t)(salt[i % 16] ^ (uint8_t)password[i % password_len]);

    stream = fopen(trace, "a");
    if (!stream) return -1;
    if (fputs("derive\n", stream) == EOF) {
        (void)fclose(stream);
        return -1;
    }
    if (fclose(stream) != 0) return -1;

    start = clock();
    if (start == (clock_t)-1) return -1;
    do {
        now = clock();
        if (now == (clock_t)-1) return -1;
    } while ((double)(now - start) / (double)CLOCKS_PER_SEC < 0.030);
    return 0;
}

EOF

"$CC" -I"$TMP/include" -std=c11 -Wall -Wextra -Werror -O2 \
    -c "$TMP/fake_sdk.c" -o "$TMP/fake_sdk.o"

verify_provider_run() {
    label=$1
    log=$2
    status=$3

    if [ "$status" -ne 0 ]; then
        printf 'FAIL: %s exited %s\n' "$label" "$status" >&2
        sed 's/^/  /' "$log" >&2
        exit 1
    fi
    if grep -Fq 'SKIP:' "$log"; then
        printf 'FAIL: %s was silently skipped\n' "$label" >&2
        sed 's/^/  /' "$log" >&2
        exit 1
    fi
    if ! grep -Fq 'F-15 KDF transparency: 5 passed, 0 failed' "$log" ||
       [ "$(wc -l <"$TMP/derive.trace")" -ne 5 ]; then
        printf 'FAIL: %s did not execute all configured provider KDF checks\n' \
            "$label" >&2
        sed 's/^/  /' "$log" >&2
        exit 1
    fi
    printf 'PASS: %s\n' "$label"
}

if ZUPT_TEST_SDK_TRACE="$TMP/derive.trace" \
   SDK_CPPFLAGS="-I$TMP/include" \
   SDK_LDLIBS="$TMP/fake_sdk.o" \
   CC="$CC" bash "$ROOT/tests/test_kdf_transparency.sh" \
   >"$TMP/harness.log" 2>&1; then
    rc=0
else
    rc=$?
fi

verify_provider_run 'configured SDK provider executes the KDF transparency harness' \
    "$TMP/harness.log" "$rc"

cat >"$TMP/make-pkg-config" <<'EOF'
#!/bin/sh
set -eu
case ${1:-} in
    --cflags)
        printf -- '-I%s/include\n' "$ZUPT_TEST_SDK_ROOT"
        ;;
    --libs)
        printf -- '%s/fake_sdk.o\n' \
            "$ZUPT_TEST_SDK_ROOT"
        ;;
    *)
        exit 1
        ;;
esac
EOF
chmod +x "$TMP/make-pkg-config"

mkdir -p "$TMP/no-provider-bin"
cat >"$TMP/no-provider-bin/pkg-config" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$TMP/no-provider-bin/pkg-config"

: >"$TMP/derive.trace"
if PATH="$TMP/no-provider-bin:$PATH" \
   ZUPT_TEST_SDK_ROOT="$TMP" ZUPT_TEST_SDK_TRACE="$TMP/derive.trace" \
   "$MAKE" -C "$ROOT" --no-print-directory WITH_SDK=1 \
   PKG_CONFIG="$TMP/make-pkg-config" CC="$CC" \
   test-kdf-transparency >"$TMP/make-harness.log" 2>&1; then
    rc=0
else
    rc=$?
fi

verify_provider_run 'Make forwards its configured SDK provider to the KDF harness' \
    "$TMP/make-harness.log" "$rc"

if PATH="$TMP/no-provider-bin:$PATH" SDK_CPPFLAGS='' SDK_LDLIBS='' \
   CC="$CC" bash "$ROOT/tests/test_kdf_transparency.sh" \
   >"$TMP/no-provider.log" 2>&1; then
    rc=0
else
    rc=$?
fi
if [ "$rc" -ne 0 ] || \
   ! grep -Fqx '  SKIP: system libvuptsdk development package unavailable' \
       "$TMP/no-provider.log"; then
    printf '%s\n' 'FAIL: unavailable SDK provider was not reported as a truthful SKIP' >&2
    sed 's/^/  /' "$TMP/no-provider.log" >&2
    exit 1
fi

printf '%s\n' 'PASS: unavailable SDK provider remains an explicit SKIP'
