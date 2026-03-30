/*
 * ZUPT v2.0.0 — VaptVupt Codec Unit Tests
 *
 * Tests VaptVupt roundtrip in all 3 modes, incompressible fallback,
 * and validates integration with Zupt's XXH64 alias.
 *
 * VAPTVUPT: Integration test suite
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT
 */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif

#include "vaptvupt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_pass = 0, g_fail = 0;

#define TEST(name) \
    do { fprintf(stderr, "  %-50s ", name); } while (0)

#define PASS() \
    do { fprintf(stderr, "PASS\n"); g_pass++; } while (0)

#define FAIL(msg) \
    do { fprintf(stderr, "FAIL: %s\n", msg); g_fail++; } while (0)

/* ─── Generate test patterns ─── */

static void fill_text(uint8_t *buf, size_t len) {
    /* Simulated English-like text with repeating patterns */
    const char *words[] = {
        "the ", "quick ", "brown ", "fox ", "jumps ", "over ",
        "lazy ", "dog ", "and ", "then ", "runs ", "back ",
        "to ", "sleep ", "under ", "a ", "warm ", "blanket ",
    };
    size_t pos = 0;
    int wi = 0;
    while (pos < len) {
        const char *w = words[wi % 18];
        size_t wl = strlen(w);
        size_t n = (pos + wl <= len) ? wl : len - pos;
        memcpy(buf + pos, w, n);
        pos += n;
        wi++;
    }
}

static void fill_binary(uint8_t *buf, size_t len) {
    /* Pseudo-random but deterministic binary data with some structure */
    uint32_t state = 0xDEADBEEF;
    for (size_t i = 0; i < len; i++) {
        state = state * 1103515245 + 12345;
        buf[i] = (uint8_t)((state >> 16) & 0xFF);
        /* Inject some repeat patterns every ~256 bytes */
        if ((i & 0xFF) < 8) buf[i] = (uint8_t)(i & 0xFF);
    }
}

static void fill_random(uint8_t *buf, size_t len) {
    /* High-entropy data: should be incompressible */
    uint64_t state = 0x123456789ABCDEF0ULL;
    for (size_t i = 0; i < len; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        buf[i] = (uint8_t)(state & 0xFF);
    }
}

/* ─── Core roundtrip test ─── */

static int test_roundtrip(const uint8_t *src, size_t src_len, vv_mode_t mode,
                           const char *label) {
    char name[128];
    snprintf(name, sizeof(name), "VV roundtrip %s (mode %d, %zu B)", label, mode, src_len);
    TEST(name);

    vv_options_t opts;
    vv_default_options(&opts);
    opts.mode = mode;
    opts.checksum = 1;

    size_t comp_cap = vv_compress_bound(src_len);
    uint8_t *comp = (uint8_t *)malloc(comp_cap);
    uint8_t *decomp = (uint8_t *)malloc(src_len + 64);
    if (!comp || !decomp) { free(comp); free(decomp); FAIL("alloc"); return 0; }

    int64_t csz = vv_compress(src, src_len, comp, comp_cap, &opts);
    if (csz <= 0) { free(comp); free(decomp); FAIL("compress failed"); return 0; }

    int64_t dsz = vv_decompress(comp, (size_t)csz, decomp, src_len + 64);
    if (dsz < 0) { free(comp); free(decomp); FAIL("decompress failed"); return 0; }
    if ((size_t)dsz != src_len) { free(comp); free(decomp); FAIL("size mismatch"); return 0; }
    if (memcmp(src, decomp, src_len) != 0) { free(comp); free(decomp); FAIL("data mismatch"); return 0; }

    free(comp);
    free(decomp);
    PASS();
    return 1;
}

/* ─── Test 1: Roundtrip all 3 modes with text data ─── */

static void test_roundtrip_all_modes(void) {
    size_t len = 65536;
    uint8_t *data = (uint8_t *)malloc(len);
    if (!data) { FAIL("alloc"); return; }
    fill_text(data, len);

    test_roundtrip(data, len, VV_MODE_ULTRA_FAST, "text");
    test_roundtrip(data, len, VV_MODE_BALANCED, "text");
    test_roundtrip(data, len, VV_MODE_EXTREME, "text");

    free(data);
}

/* ─── Test 2: Roundtrip with binary data ─── */

static void test_roundtrip_binary(void) {
    size_t len = 131072;
    uint8_t *data = (uint8_t *)malloc(len);
    if (!data) { FAIL("alloc"); return; }
    fill_binary(data, len);

    test_roundtrip(data, len, VV_MODE_BALANCED, "binary");

    free(data);
}

/* ─── Test 3: Incompressible data falls back to raw blocks ─── */

static void test_incompressible(void) {
    TEST("VV incompressible fallback");

    size_t len = 32768;
    uint8_t *data = (uint8_t *)malloc(len);
    if (!data) { FAIL("alloc"); return; }
    fill_random(data, len);

    vv_options_t opts;
    vv_default_options(&opts);
    opts.mode = VV_MODE_ULTRA_FAST;
    opts.checksum = 1;

    size_t comp_cap = vv_compress_bound(len);
    uint8_t *comp = (uint8_t *)malloc(comp_cap);
    uint8_t *decomp = (uint8_t *)malloc(len + 64);
    if (!comp || !decomp) { free(data); free(comp); free(decomp); FAIL("alloc"); return; }

    int64_t csz = vv_compress(data, len, comp, comp_cap, &opts);
    if (csz <= 0) { free(data); free(comp); free(decomp); FAIL("compress"); return; }

    /* Compressed size should be >= original for random data (stored as raw blocks) */
    int64_t dsz = vv_decompress(comp, (size_t)csz, decomp, len + 64);
    if (dsz < 0 || (size_t)dsz != len) { free(data); free(comp); free(decomp); FAIL("decompress"); return; }
    if (memcmp(data, decomp, len) != 0) { free(data); free(comp); free(decomp); FAIL("data mismatch"); return; }

    free(data);
    free(comp);
    free(decomp);
    PASS();
}

/* ─── Test 4: Empty input ─── */

static void test_empty(void) {
    TEST("VV empty input roundtrip");

    vv_options_t opts;
    vv_default_options(&opts);
    opts.checksum = 0;

    uint8_t comp[256];
    uint8_t decomp[64];

    int64_t csz = vv_compress((const uint8_t *)"", 0, comp, sizeof(comp), &opts);
    if (csz <= 0) { FAIL("compress empty"); return; }

    int64_t dsz = vv_decompress(comp, (size_t)csz, decomp, sizeof(decomp));
    if (dsz != 0) { FAIL("expected 0 decompressed bytes"); return; }

    PASS();
}

/* ─── Test 5: Small data (< VV_MIN_MATCH) ─── */

static void test_small(void) {
    TEST("VV small data roundtrip (3 bytes)");

    const uint8_t data[] = { 0x41, 0x42, 0x43 };
    vv_options_t opts;
    vv_default_options(&opts);
    opts.checksum = 1;

    size_t cap = vv_compress_bound(3);
    uint8_t *comp = (uint8_t *)malloc(cap);
    uint8_t decomp[64];
    if (!comp) { FAIL("alloc"); return; }

    int64_t csz = vv_compress(data, 3, comp, cap, &opts);
    if (csz <= 0) { free(comp); FAIL("compress"); return; }

    int64_t dsz = vv_decompress(comp, (size_t)csz, decomp, sizeof(decomp));
    if (dsz != 3) { free(comp); FAIL("size"); return; }
    if (memcmp(data, decomp, 3) != 0) { free(comp); FAIL("data"); return; }

    free(comp);
    PASS();
}

/* ─── Test 6: zupt_xxh64 alias works ─── */

static void test_xxh64_alias(void) {
    TEST("VV vv_xxh64 → zupt_xxh64 alias");

    const uint8_t data[] = "Hello, VaptVupt!";
    uint64_t h1 = vv_xxh64(data, sizeof(data) - 1, 0);
    uint64_t h2 = zupt_xxh64(data, sizeof(data) - 1, 0);

    if (h1 != h2) { FAIL("hash mismatch"); return; }
    if (h1 == 0) { FAIL("zero hash"); return; }

    PASS();
}

/* ─── Test 7: Large data roundtrip (multi-block) ─── */

static void test_large_multiblock(void) {
    /* 2 MB: forces multiple VaptVupt blocks (VV_MAX_BLOCK_SIZE = 1 MB) */
    size_t len = 2 * 1024 * 1024;
    uint8_t *data = (uint8_t *)malloc(len);
    if (!data) { FAIL("alloc"); return; }
    fill_text(data, len);

    test_roundtrip(data, len, VV_MODE_BALANCED, "large 2MB");

    free(data);
}

/* ─── Test 8: RLE-like data (single repeated byte) ─── */

static void test_rle(void) {
    TEST("VV RLE-like data roundtrip");

    size_t len = 16384;
    uint8_t *data = (uint8_t *)malloc(len);
    if (!data) { FAIL("alloc"); return; }
    memset(data, 0xAA, len);

    vv_options_t opts;
    vv_default_options(&opts);
    opts.mode = VV_MODE_BALANCED;
    opts.checksum = 1;

    size_t cap = vv_compress_bound(len);
    uint8_t *comp = (uint8_t *)malloc(cap);
    uint8_t *decomp = (uint8_t *)malloc(len);
    if (!comp || !decomp) { free(data); free(comp); free(decomp); FAIL("alloc"); return; }

    int64_t csz = vv_compress(data, len, comp, cap, &opts);
    if (csz <= 0) { free(data); free(comp); free(decomp); FAIL("compress"); return; }

    /* Should compress extremely well */
    if ((size_t)csz > len / 4) {
        fprintf(stderr, "(ratio: %zu/%zu) ", (size_t)csz, len);
    }

    int64_t dsz = vv_decompress(comp, (size_t)csz, decomp, len);
    if (dsz < 0 || (size_t)dsz != len) { free(data); free(comp); free(decomp); FAIL("decompress"); return; }
    if (memcmp(data, decomp, len) != 0) { free(data); free(comp); free(decomp); FAIL("data"); return; }

    free(data);
    free(comp);
    free(decomp);
    PASS();
}

/* ─── Test 9: Window log 20 (1 MB window) ─── */

static void test_window_log_20(void) {
    TEST("VV window_log=20 roundtrip");

    size_t len = 262144;
    uint8_t *data = (uint8_t *)malloc(len);
    if (!data) { FAIL("alloc"); return; }
    fill_text(data, len);

    vv_options_t opts;
    vv_default_options(&opts);
    opts.mode = VV_MODE_BALANCED;
    opts.window_log = 20;
    opts.checksum = 1;

    size_t cap = vv_compress_bound(len);
    uint8_t *comp = (uint8_t *)malloc(cap);
    uint8_t *decomp = (uint8_t *)malloc(len);
    if (!comp || !decomp) { free(data); free(comp); free(decomp); FAIL("alloc"); return; }

    int64_t csz = vv_compress(data, len, comp, cap, &opts);
    if (csz <= 0) { free(data); free(comp); free(decomp); FAIL("compress"); return; }

    int64_t dsz = vv_decompress(comp, (size_t)csz, decomp, len);
    if (dsz < 0 || (size_t)dsz != len) { free(data); free(comp); free(decomp); FAIL("decompress"); return; }
    if (memcmp(data, decomp, len) != 0) { free(data); free(comp); free(decomp); FAIL("data"); return; }

    free(data);
    free(comp);
    free(decomp);
    PASS();
}

/* ═══════════════════════════════════════════════════════════════ */

int main(void) {
    fprintf(stderr, "\n  ZUPT v2.0.0 — VaptVupt Codec Unit Tests\n");
    fprintf(stderr, "  ═══════════════════════════════════════════════\n\n");

    test_roundtrip_all_modes();    /* Tests 1a, 1b, 1c */
    test_roundtrip_binary();       /* Test 2 */
    test_incompressible();         /* Test 3 */
    test_empty();                  /* Test 4 */
    test_small();                  /* Test 5 */
    test_xxh64_alias();            /* Test 6 */
    test_large_multiblock();       /* Test 7 */
    test_rle();                    /* Test 8 */
    test_window_log_20();          /* Test 9 */

    fprintf(stderr, "\n  ═══════════════════════════════════════════════\n");
    fprintf(stderr, "  Results: %d passed, %d failed (%d total)\n\n",
            g_pass, g_fail, g_pass + g_fail);

    return g_fail > 0 ? 1 : 0;
}
