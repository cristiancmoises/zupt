/*
 * libzuptsdk example: compress a file with a password, then extract it.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Build: gcc example.c $(pkg-config --cflags --libs zuptsdk) -o example
 *        # or, before installation:
 *        gcc example.c -I sdk/include -L sdk/build -lzuptsdk \
 *            -Wl,-rpath,'$ORIGIN/../build' -o example
 */
#include <zuptsdk.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int die(const char *what, int rc) {
    fprintf(stderr, "ERROR (%s): %s\n", what, zuptsdk_strerror(rc));
    fprintf(stderr, "  detail: %s\n", zuptsdk_last_error_detail());
    return 1;
}

int main(void) {
    /* 1. Always check ABI compatibility at startup */
    int rc = zuptsdk_version_check(1, 0, 0);
    if (rc) return die("version_check", rc);
    printf("libzuptsdk %s\n\n", zuptsdk_version_string());

    /* 2. Create a context (cheap; one per worker thread is fine) */
    zuptsdk_ctx_t *ctx = NULL;
    rc = zuptsdk_ctx_create(&ctx);
    if (rc) return die("ctx_create", rc);

    /* 3. Wrap a password in a secure buffer (mlock + zero on destroy) */
    zuptsdk_secure_buf_t *pw = NULL;
    const char *password = "correct horse battery staple";
    rc = zuptsdk_secure_buf_from_data((const uint8_t *)password,
                                      strlen(password), &pw);
    if (rc) { zuptsdk_ctx_destroy(ctx); return die("secure_buf", rc); }

    /* 4. Compress some data into a memory archive */
    const char *plaintext = "This is the secret data we want to protect.\n";
    uint8_t *archive = NULL;
    size_t archive_sz = 0;
    rc = zuptsdk_compress_buffer(ctx, NULL,
                                 "secret.txt",
                                 (const uint8_t *)plaintext, strlen(plaintext),
                                 pw, NULL,
                                 &archive, &archive_sz);
    if (rc) {
        zuptsdk_secure_buf_destroy(pw);
        zuptsdk_ctx_destroy(ctx);
        return die("compress_buffer", rc);
    }
    printf("Compressed %zu bytes -> %zu byte archive\n", strlen(plaintext), archive_sz);

    /* 5. Extract it back, verifying byte-for-byte */
    uint8_t *extracted = NULL;
    size_t extracted_sz = 0;
    rc = zuptsdk_extract_buffer(ctx, archive, archive_sz,
                                pw, NULL,
                                &extracted, &extracted_sz);
    if (rc) {
        zuptsdk_free(archive);
        zuptsdk_secure_buf_destroy(pw);
        zuptsdk_ctx_destroy(ctx);
        return die("extract_buffer", rc);
    }

    /* 6. Verify */
    int ok = (extracted_sz == strlen(plaintext)) &&
             (memcmp(extracted, plaintext, extracted_sz) == 0);
    printf("Roundtrip: %s\n", ok ? "OK (byte-exact)" : "FAILED");
    printf("Extracted: %.*s", (int)extracted_sz, extracted);

    /* 7. Clean up — always use zuptsdk_free for transferred memory */
    zuptsdk_free(extracted);
    zuptsdk_free(archive);
    zuptsdk_secure_buf_destroy(pw);
    zuptsdk_ctx_destroy(ctx);
    return ok ? 0 : 1;
}
