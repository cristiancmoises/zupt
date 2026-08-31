/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Exact-content_size decode regression (v4.0.0; codec 2.60.4).
 *
 * Codec 2.60.4 fixes a high-severity OOB heap WRITE in the AVX2 decode
 * fast path, reachable on a VALID stream when the destination buffer is
 * sized to exactly content_size — two variants: a single wide store for
 * tails n <= 32, and the tail store for n > 32. The tool itself always
 * over-allocates (ZUPT_VV_DECODE_SLACK, F-14), so it was shielded; this
 * test pins the vendored codec directly so the defect class cannot
 * silently return via a future codec drop-in.
 *
 * Method: for payloads chosen to exercise (a) sizes whose tail mod 32
 * spans 1..32 and >32, (b) compressible text, (c) BCJ-triggering
 * ELF-like content (auto-filter on), compress with the same options the
 * tool's shim uses (BALANCED and EXTREME, format_v2, filter_auto), then
 * decompress into a heap buffer of EXACTLY the original size, under
 * AddressSanitizer. Any OOB write aborts the test. Output must also be
 * byte-identical to the input (BCJ inverse correctness).
 */
#include "vaptvupt.h"
#include "vaptvupt_api.h"
#include "vv_bcj.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int run_case(const uint8_t *src, size_t n, int mode, const char *label) {
    vv_options_t opts;
    vv_default_options(&opts);
    opts.checksum    = 0;
    opts.compat_v246_5_decoder = 0;
    opts.mode        = mode;
    opts.format_v2   = 1;
    opts.filter_auto = 1;
    opts.window_log  = 0;

    size_t cap = vv_compress_bound(n);
    uint8_t *comp = (uint8_t *)malloc(cap);
    if (!comp) { fprintf(stderr, "  OOM\n"); return 1; }
    int64_t csz = vv_compress(src, n, comp, cap, &opts);
    if (csz <= 0) { fprintf(stderr, "  %s: compress failed (%lld)\n", label, (long long)csz); free(comp); return 1; }

    /* EXACT-size destination — the CVE trigger. ASan owns the verdict on
     * any out-of-bounds write. */
    uint8_t *out = (uint8_t *)malloc(n ? n : 1);
    if (!out) { free(comp); return 1; }
    int64_t dsz = vv_decompress_flags(comp, (size_t)csz, out, n,
                                      VV_DECOMPRESS_SKIP_CHECKSUM);
    int rc = 0;
    if (dsz != (int64_t)n)                 { fprintf(stderr, "  %s: size %lld != %zu\n", label, (long long)dsz, n); rc = 1; }
    else if (memcmp(out, src, n) != 0)     { fprintf(stderr, "  %s: payload mismatch\n", label); rc = 1; }
    free(out); free(comp);
    return rc;
}

/* Synthetic ELF-ish buffer: real ELF magic + class/endian bytes so
 * vv_bcj_detect engages the x86 filter, then bytes containing E8/E9
 * (call/jmp rel32) patterns that the filter actually rewrites. */
static void fill_elfish(uint8_t *p, size_t n) {
    static const uint8_t elf_hdr[20] = {
        0x7f,'E','L','F', 2,1,1,0, 0,0,0,0,0,0,0,0, 2,0, 0x3e,0
    };
    memset(p, 0, n);
    memcpy(p, elf_hdr, n < 20 ? n : 20);
    for (size_t i = 24; i + 5 < n; i += 7) {
        p[i] = (i % 3) ? 0xE8 : 0xE9;           /* call / jmp */
        uint32_t rel = (uint32_t)(i * 2654435761u);
        memcpy(p + i + 1, &rel, 4);
    }
}

static uint32_t bcj_prng_state = 0x7a5b3c1du;

static uint32_t bcj_prng(void) {
    uint32_t x = bcj_prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    bcj_prng_state = x;
    return x;
}

static int test_bcj_bijections(void) {
    uint8_t original[4097];
    uint8_t transformed[4097];

    for (unsigned iteration = 0; iteration < 1024; iteration++) {
        size_t n = (size_t)(bcj_prng() % sizeof(original));
        uint32_t ip = bcj_prng();
        for (size_t i = 0; i < n; i++)
            original[i] = (uint8_t)bcj_prng();

        /* Force dense branch-like operands in half the corpus so both filters
         * exercise their rewrite paths rather than only scanning random data. */
        if ((iteration & 1u) != 0) {
            for (size_t i = 0; i < n; i++) {
                static const uint8_t pattern[] = {
                    0xe8, 0x00, 0x00, 0x00, 0x00,
                    0xe9, 0xff, 0xff, 0xff, 0xff,
                    0x00, 0x00, 0x00, 0x94
                };
                original[i] = pattern[i % sizeof(pattern)];
            }
        }

        memcpy(transformed, original, n);
        (void)vv_bcj_x86(transformed, n, ip, 1);
        (void)vv_bcj_x86(transformed, n, ip, 0);
        if (memcmp(transformed, original, n) != 0) {
            fprintf(stderr, "  x86 BCJ bijection failed: iteration=%u size=%zu\n",
                    iteration, n);
            return 1;
        }

        memcpy(transformed, original, n);
        (void)vv_bcj_arm64(transformed, n, ip, 1);
        (void)vv_bcj_arm64(transformed, n, ip, 0);
        if (memcmp(transformed, original, n) != 0) {
            fprintf(stderr, "  AArch64 BCJ bijection failed: iteration=%u size=%zu\n",
                    iteration, n);
            return 1;
        }
    }
    printf("  BCJ bijections: 1024 deterministic randomized/adversarial cases passed\n");
    return 0;
}

int main(void) {
    printf("Codec exact-content_size decode (OOB regression, codec 2.60.4)\n");
    srand(424242);
    int fail = 0, pass = 0;

    if (test_bcj_bijections() != 0)
        fail++;
    else
        pass++;

    /* Tail coverage: n mod 32 in {1, 7, 31, 32 (0), >32 leftovers} at
     * block-ish sizes, plus tiny buffers. */
    static const size_t sizes[] = {
        1, 7, 31, 32, 33, 63, 64, 65, 96, 4095, 4096, 4097,
        65536 + 1, 65536 + 31, 65536 + 33, 1048576 + 17
    };
    enum { NSZ = sizeof(sizes)/sizeof(sizes[0]) };

    uint8_t *buf = (uint8_t *)malloc(1048576 + 64);
    if (!buf) return 1;

    for (int k = 0; k < NSZ; k++) {
        size_t n = sizes[k];
        char label[96];

        /* compressible text-like */
        for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)("abcdef \n"[i % 8]);
        snprintf(label, sizeof label, "text n=%zu BALANCED", n);
        if (run_case(buf, n, VV_MODE_BALANCED, label)) fail++; else pass++;
        snprintf(label, sizeof label, "text n=%zu EXTREME", n);
        if (run_case(buf, n, VV_MODE_EXTREME, label)) fail++; else pass++;

        /* BCJ-triggering ELF-ish (filter_auto fires) */
        fill_elfish(buf, n);
        snprintf(label, sizeof label, "elf  n=%zu BALANCED", n);
        if (run_case(buf, n, VV_MODE_BALANCED, label)) fail++; else pass++;
        snprintf(label, sizeof label, "elf  n=%zu EXTREME", n);
        if (run_case(buf, n, VV_MODE_EXTREME, label)) fail++; else pass++;

        /* incompressible (stored path) */
        for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rand();
        snprintf(label, sizeof label, "rand n=%zu BALANCED", n);
        if (run_case(buf, n, VV_MODE_BALANCED, label)) fail++; else pass++;
    }
    free(buf);

    printf("\n  ───────────────────────────────────────\n");
    printf("  exact-size decode: %d passed, %d failed\n", pass, fail);
    printf("  ───────────────────────────────────────\n");
    return fail ? 1 : 0;
}
