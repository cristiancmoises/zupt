/*
 * libzuptsdk roundtrip test
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Exercises every public SDK function with a byte-exact verification.
 * Returns 0 on success; non-zero on any failure.
 */

#define _DEFAULT_SOURCE 1
#include <zuptsdk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_pass = 0, g_fail = 0;

#define TEST(name) do { \
    fprintf(stderr, "  %-60s", name); \
    fflush(stderr); \
} while (0)

#define PASS() do { \
    fprintf(stderr, "PASS\n"); \
    g_pass++; \
} while (0)

#define FAIL(reason) do { \
    fprintf(stderr, "FAIL: %s\n", reason); \
    if (zuptsdk_last_error_detail()[0]) \
        fprintf(stderr, "       detail: %s\n", zuptsdk_last_error_detail()); \
    g_fail++; \
} while (0)

#define CHECK(rc, msg) do { \
    if ((rc) != ZUPTSDK_OK) { FAIL(msg); return; } \
} while (0)

static const uint8_t TEST_DATA[] =
    "Post-quantum backup test data for the libzuptsdk roundtrip suite. "
    "This payload is repeated to ensure compression actually does something. "
    "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod. "
    "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod. "
    "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod. "
    "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod. "
    "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod. "
    "End of test data.\n";

static void test_version(void) {
    TEST("version_string returns non-NULL");
    const char *v = zuptsdk_version_string();
    if (!v || strlen(v) == 0) { FAIL("empty"); return; }
    if (strcmp(v, ZUPTSDK_VERSION_STRING) != 0) { FAIL("mismatch"); return; }
    PASS();

    TEST("version_check accepts current version");
    int rc = zuptsdk_version_check(ZUPTSDK_VERSION_MAJOR,
                                   ZUPTSDK_VERSION_MINOR,
                                   ZUPTSDK_VERSION_PATCH);
    CHECK(rc, "rejected own version");
    PASS();

    TEST("version_check rejects future version");
    rc = zuptsdk_version_check(99, 99, 99);
    if (rc != ZUPTSDK_ERR_VERSION_MISMATCH) { FAIL("should reject"); return; }
    PASS();
}

static void test_strerror(void) {
    TEST("strerror handles every error code");
    for (int e = 0; e >= -100; e--) {
        const char *s = zuptsdk_strerror(e);
        if (!s || !*s) { FAIL("empty"); return; }
    }
    PASS();
}

static void test_context(void) {
    TEST("ctx_create / ctx_destroy");
    zuptsdk_ctx_t *c = NULL;
    CHECK(zuptsdk_ctx_create(&c), "create failed");
    if (!c) { FAIL("ctx is NULL"); return; }
    zuptsdk_ctx_destroy(c);
    zuptsdk_ctx_destroy(NULL); /* should not crash */
    PASS();

    TEST("ctx_set_threads validates range");
    CHECK(zuptsdk_ctx_create(&c), "create");
    int rc = zuptsdk_ctx_set_threads(c, 0);   /* auto */
    CHECK(rc, "auto");
    rc = zuptsdk_ctx_set_threads(c, 4);       /* normal */
    CHECK(rc, "4");
    rc = zuptsdk_ctx_set_threads(c, -1);      /* invalid */
    if (rc != ZUPTSDK_ERR_INVALID_ARG) { FAIL("should reject -1"); zuptsdk_ctx_destroy(c); return; }
    rc = zuptsdk_ctx_set_threads(c, 999);     /* invalid */
    if (rc != ZUPTSDK_ERR_INVALID_ARG) { FAIL("should reject 999"); zuptsdk_ctx_destroy(c); return; }
    zuptsdk_ctx_destroy(c);
    PASS();
}

static void test_options(void) {
    TEST("options builder full sequence");
    zuptsdk_options_t *o = NULL;
    CHECK(zuptsdk_options_create(&o), "create");
    CHECK(zuptsdk_options_set_codec(o, ZUPTSDK_CODEC_AUTO), "codec auto");
    CHECK(zuptsdk_options_set_codec(o, ZUPTSDK_CODEC_VAPTVUPT), "codec vv");
    CHECK(zuptsdk_options_set_level(o, 7), "level 7");
    CHECK(zuptsdk_options_set_dedup(o, 1), "dedup");
    CHECK(zuptsdk_options_set_solid(o, 0), "solid");
    CHECK(zuptsdk_options_set_max_decompressed(o, 1024 * 1024), "max");
    int rc = zuptsdk_options_set_level(o, 99);
    if (rc != ZUPTSDK_ERR_INVALID_ARG) { FAIL("level 99 should fail"); zuptsdk_options_destroy(o); return; }
    zuptsdk_options_destroy(o);
    PASS();
}

static void test_secure_buf(void) {
    TEST("secure_buf create/get/destroy");
    zuptsdk_secure_buf_t *b = NULL;
    CHECK(zuptsdk_secure_buf_create(64, &b), "create");
    uint8_t *data = NULL; size_t sz = 0;
    CHECK(zuptsdk_secure_buf_get(b, &data, &sz), "get");
    if (sz != 64) { FAIL("size wrong"); zuptsdk_secure_buf_destroy(b); return; }
    memset(data, 0xAA, 64);
    if (data[0] != 0xAA || data[63] != 0xAA) { FAIL("write/read"); zuptsdk_secure_buf_destroy(b); return; }
    zuptsdk_secure_buf_destroy(b);
    PASS();

    TEST("secure_buf_from_data copies");
    const uint8_t src[] = "secret password value!";
    CHECK(zuptsdk_secure_buf_from_data(src, sizeof(src) - 1, &b), "from_data");
    CHECK(zuptsdk_secure_buf_get(b, &data, &sz), "get");
    if (sz != sizeof(src) - 1) { FAIL("size"); zuptsdk_secure_buf_destroy(b); return; }
    if (memcmp(data, src, sz) != 0) { FAIL("content"); zuptsdk_secure_buf_destroy(b); return; }
    zuptsdk_secure_buf_destroy(b);
    PASS();
}

static int byteexact(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
    return (na == nb) && (memcmp(a, b, na) == 0);
}

static void test_compress_buffer_plain(void) {
    TEST("compress_buffer + extract_buffer (plain)");
    zuptsdk_ctx_t *ctx = NULL;
    CHECK(zuptsdk_ctx_create(&ctx), "ctx");

    zuptsdk_options_t *opts = NULL;
    CHECK(zuptsdk_options_create(&opts), "opts");
    zuptsdk_options_set_codec(opts, ZUPTSDK_CODEC_AUTO);
    zuptsdk_options_set_level(opts, 5);

    uint8_t *arc = NULL; size_t arc_sz = 0;
    int rc = zuptsdk_compress_buffer(ctx, opts, "test.txt",
                                     TEST_DATA, sizeof(TEST_DATA) - 1,
                                     NULL, NULL, &arc, &arc_sz);
    if (rc != ZUPTSDK_OK) { FAIL("compress"); zuptsdk_options_destroy(opts); zuptsdk_ctx_destroy(ctx); return; }

    uint8_t *out = NULL; size_t out_sz = 0;
    rc = zuptsdk_extract_buffer(ctx, arc, arc_sz, NULL, NULL, &out, &out_sz);
    zuptsdk_free(arc);

    if (rc != ZUPTSDK_OK) { FAIL("extract"); zuptsdk_options_destroy(opts); zuptsdk_ctx_destroy(ctx); return; }
    if (!byteexact(out, out_sz, TEST_DATA, sizeof(TEST_DATA) - 1)) {
        FAIL("byte mismatch");
        zuptsdk_free(out);
        zuptsdk_options_destroy(opts);
        zuptsdk_ctx_destroy(ctx);
        return;
    }
    zuptsdk_free(out);
    zuptsdk_options_destroy(opts);
    zuptsdk_ctx_destroy(ctx);
    PASS();
}

static void test_compress_buffer_password(void) {
    TEST("compress_buffer + extract_buffer (password)");
    zuptsdk_ctx_t *ctx = NULL;
    CHECK(zuptsdk_ctx_create(&ctx), "ctx");

    zuptsdk_options_t *opts = NULL;
    CHECK(zuptsdk_options_create(&opts), "opts");

    zuptsdk_secure_buf_t *pw = NULL;
    const uint8_t pwbuf[] = "Tr0ub4dor&3";
    CHECK(zuptsdk_secure_buf_from_data(pwbuf, sizeof(pwbuf) - 1, &pw), "pw create");

    uint8_t *arc = NULL; size_t arc_sz = 0;
    int rc = zuptsdk_compress_buffer(ctx, opts, "secret.txt",
                                     TEST_DATA, sizeof(TEST_DATA) - 1,
                                     pw, NULL, &arc, &arc_sz);
    if (rc != ZUPTSDK_OK) {
        FAIL("compress");
        zuptsdk_secure_buf_destroy(pw);
        zuptsdk_options_destroy(opts);
        zuptsdk_ctx_destroy(ctx);
        return;
    }

    uint8_t *out = NULL; size_t out_sz = 0;
    rc = zuptsdk_extract_buffer(ctx, arc, arc_sz, pw, NULL, &out, &out_sz);
    zuptsdk_free(arc);

    int ok = (rc == ZUPTSDK_OK) && byteexact(out, out_sz, TEST_DATA, sizeof(TEST_DATA) - 1);
    zuptsdk_free(out);
    zuptsdk_secure_buf_destroy(pw);
    zuptsdk_options_destroy(opts);
    zuptsdk_ctx_destroy(ctx);
    if (!ok) { FAIL("byte mismatch or rc != OK"); return; }
    PASS();
}

static void test_compress_buffer_wrong_password(void) {
    TEST("extract_buffer rejects wrong password");
    zuptsdk_ctx_t *ctx = NULL;
    CHECK(zuptsdk_ctx_create(&ctx), "ctx");

    zuptsdk_options_t *opts = NULL;
    CHECK(zuptsdk_options_create(&opts), "opts");

    zuptsdk_secure_buf_t *pw_good = NULL, *pw_bad = NULL;
    zuptsdk_secure_buf_from_data((const uint8_t*)"correct", 7, &pw_good);
    zuptsdk_secure_buf_from_data((const uint8_t*)"WRONG-pw", 8, &pw_bad);

    uint8_t *arc = NULL; size_t arc_sz = 0;
    int rc = zuptsdk_compress_buffer(ctx, opts, "x.txt",
                                     TEST_DATA, sizeof(TEST_DATA) - 1,
                                     pw_good, NULL, &arc, &arc_sz);
    if (rc != ZUPTSDK_OK) { FAIL("compress"); goto cleanup; }

    uint8_t *out = NULL; size_t out_sz = 0;
    rc = zuptsdk_extract_buffer(ctx, arc, arc_sz, pw_bad, NULL, &out, &out_sz);
    if (rc == ZUPTSDK_OK) {
        FAIL("wrong password accepted");
        zuptsdk_free(out);
        zuptsdk_free(arc);
        goto cleanup;
    }
    zuptsdk_free(arc);
    PASS();

cleanup:
    zuptsdk_secure_buf_destroy(pw_good);
    zuptsdk_secure_buf_destroy(pw_bad);
    zuptsdk_options_destroy(opts);
    zuptsdk_ctx_destroy(ctx);
}

static void test_keypair_pq(void) {
    TEST("keypair_generate + compress_pq + extract_pq");
    zuptsdk_ctx_t *ctx = NULL;
    CHECK(zuptsdk_ctx_create(&ctx), "ctx");

    zuptsdk_keypair_t *kp = NULL;
    int rc = zuptsdk_keypair_generate(ctx, &kp);
    if (rc != ZUPTSDK_OK) { FAIL("keygen"); zuptsdk_ctx_destroy(ctx); return; }

    /* Save and load to exercise that path too */
    rc = zuptsdk_keypair_save_private(kp, "/tmp/_zsdk_priv.key");
    if (rc != ZUPTSDK_OK) { FAIL("save priv"); goto err; }
    rc = zuptsdk_keypair_save_public(kp, "/tmp/_zsdk_pub.key");
    if (rc != ZUPTSDK_OK) { FAIL("save pub"); goto err; }

    zuptsdk_pubkey_t *pub = NULL;
    zuptsdk_privkey_t *priv = NULL;
    rc = zuptsdk_pubkey_load("/tmp/_zsdk_pub.key", &pub);
    if (rc != ZUPTSDK_OK) { FAIL("load pub"); goto err; }
    rc = zuptsdk_privkey_load("/tmp/_zsdk_priv.key", &priv);
    if (rc != ZUPTSDK_OK) { FAIL("load priv"); zuptsdk_pubkey_destroy(pub); goto err; }

    zuptsdk_options_t *opts = NULL;
    zuptsdk_options_create(&opts);

    uint8_t *arc = NULL; size_t arc_sz = 0;
    rc = zuptsdk_compress_buffer(ctx, opts, "pq.txt",
                                 TEST_DATA, sizeof(TEST_DATA) - 1,
                                 NULL, pub, &arc, &arc_sz);
    if (rc != ZUPTSDK_OK) {
        FAIL("compress_pq");
        zuptsdk_pubkey_destroy(pub);
        zuptsdk_privkey_destroy(priv);
        zuptsdk_options_destroy(opts);
        goto err;
    }

    uint8_t *out = NULL; size_t out_sz = 0;
    rc = zuptsdk_extract_buffer(ctx, arc, arc_sz, NULL, priv, &out, &out_sz);
    int ok = (rc == ZUPTSDK_OK) && byteexact(out, out_sz, TEST_DATA, sizeof(TEST_DATA) - 1);

    zuptsdk_free(arc);
    zuptsdk_free(out);
    zuptsdk_pubkey_destroy(pub);
    zuptsdk_privkey_destroy(priv);
    zuptsdk_options_destroy(opts);

    unlink("/tmp/_zsdk_priv.key");
    unlink("/tmp/_zsdk_pub.key");

    if (!ok) { FAIL("byte mismatch or rc != OK"); zuptsdk_keypair_destroy(kp); zuptsdk_ctx_destroy(ctx); return; }
    zuptsdk_keypair_destroy(kp);
    zuptsdk_ctx_destroy(ctx);
    PASS();
    return;

err:
    zuptsdk_keypair_destroy(kp);
    zuptsdk_ctx_destroy(ctx);
}

static void test_verify_and_info(void) {
    TEST("verify and archive_info_read");
    zuptsdk_ctx_t *ctx = NULL;
    CHECK(zuptsdk_ctx_create(&ctx), "ctx");
    zuptsdk_options_t *opts = NULL;
    zuptsdk_options_create(&opts);

    uint8_t *arc = NULL; size_t arc_sz = 0;
    int rc = zuptsdk_compress_buffer(ctx, opts, "v.txt",
                                     TEST_DATA, sizeof(TEST_DATA) - 1,
                                     NULL, NULL, &arc, &arc_sz);
    if (rc != ZUPTSDK_OK) { FAIL("compress"); goto cleanup; }

    rc = zuptsdk_verify(ctx, arc, arc_sz, NULL, NULL);
    if (rc != ZUPTSDK_OK) { FAIL("verify"); zuptsdk_free(arc); goto cleanup; }

    zuptsdk_archive_info_t *info = NULL;
    rc = zuptsdk_archive_info_read(ctx, arc, arc_sz, &info);
    if (rc != ZUPTSDK_OK) { FAIL("info read"); zuptsdk_free(arc); goto cleanup; }

    int major = zuptsdk_archive_info_format_major(info);
    int enc   = zuptsdk_archive_info_is_encrypted(info);
    const char *uuid = zuptsdk_archive_info_uuid(info);

    if (major < 1 || enc != 0 || !uuid || strlen(uuid) != 36) {
        fprintf(stderr, "[major=%d enc=%d uuid=%s] ", major, enc, uuid ? uuid : "NULL");
        FAIL("info fields wrong");
        zuptsdk_archive_info_destroy(info);
        zuptsdk_free(arc);
        goto cleanup;
    }

    zuptsdk_archive_info_destroy(info);
    zuptsdk_free(arc);
    PASS();

cleanup:
    zuptsdk_options_destroy(opts);
    zuptsdk_ctx_destroy(ctx);
}

static void test_corrupted_archive(void) {
    TEST("verify rejects corrupted archive");
    zuptsdk_ctx_t *ctx = NULL;
    CHECK(zuptsdk_ctx_create(&ctx), "ctx");
    zuptsdk_options_t *opts = NULL;
    zuptsdk_options_create(&opts);

    /* Build a larger archive so flipping a byte hits compressed data,
     * not a zero-padded header field. */
    size_t big_sz = (sizeof(TEST_DATA) - 1) * 100;
    uint8_t *big = (uint8_t *)malloc(big_sz);
    if (!big) { FAIL("alloc"); goto cleanup; }
    for (size_t i = 0; i < 100; i++)
        memcpy(big + i * (sizeof(TEST_DATA) - 1), TEST_DATA, sizeof(TEST_DATA) - 1);

    uint8_t *arc = NULL; size_t arc_sz = 0;
    int rc = zuptsdk_compress_buffer(ctx, opts, "c.txt", big, big_sz,
                                     NULL, NULL, &arc, &arc_sz);
    free(big);
    if (rc != ZUPTSDK_OK) { FAIL("compress"); goto cleanup; }

    /* Flip a byte two-thirds through, in the real compressed data region */
    if (arc_sz > 200) arc[(arc_sz * 2) / 3] ^= 0xFF;

    rc = zuptsdk_verify(ctx, arc, arc_sz, NULL, NULL);
    if (rc == ZUPTSDK_OK) {
        FAIL("verify accepted corrupted archive");
        zuptsdk_free(arc);
        goto cleanup;
    }
    zuptsdk_free(arc);
    PASS();

cleanup:
    zuptsdk_options_destroy(opts);
    zuptsdk_ctx_destroy(ctx);
}

int main(void) {
    fprintf(stderr, "\n═══════════════════════════════════════════════════════════════\n");
    fprintf(stderr, "  libzuptsdk %s — roundtrip test suite\n", zuptsdk_version_string());
    fprintf(stderr, "═══════════════════════════════════════════════════════════════\n\n");

    test_version();
    test_strerror();
    test_context();
    test_options();
    test_secure_buf();
    test_compress_buffer_plain();
    test_compress_buffer_password();
    test_compress_buffer_wrong_password();
    test_keypair_pq();
    test_verify_and_info();
    test_corrupted_archive();

    fprintf(stderr, "\n═══════════════════════════════════════════════════════════════\n");
    fprintf(stderr, "  Results: %d passed, %d failed\n", g_pass, g_fail);
    fprintf(stderr, "═══════════════════════════════════════════════════════════════\n\n");
    return g_fail == 0 ? 0 : 1;
}
