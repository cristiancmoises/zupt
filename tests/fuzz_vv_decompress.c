/*
 * Zupt v2.0.0 — AFL++ Fuzzing Harness: VaptVupt Codec
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Reads fuzzed VaptVupt frame data from stdin, attempts decompression.
 * Tests the VaptVupt codec directly (bypassing Zupt archive format).
 *
 * Build:
 *   afl-clang-fast -fsanitize=address,undefined -g -O1 -mavx2 \
 *     -Iinclude -Isrc tests/fuzz_vv_decompress.c \
 *     src/vv_encoder.c src/vv_decoder.c src/vv_ans.c src/vv_huffman.c \
 *     src/vv_simd.c src/zupt_xxh.c src/zupt_cpuid.c \
 *     -lm -lpthread -o fuzz_vv_decompress
 *
 * Seed corpus generation:
 *   python3 -c "print('hello world ' * 1000)" > /tmp/vv_seed.txt
 *   ./zupt compress --vv /tmp/vv_seed.zupt /tmp/vv_seed.txt
 *   # Extract the VaptVupt frame from the archive block payload
 *
 * Run:
 *   afl-fuzz -i corpus_vv -o findings_vv -- ./fuzz_vv_decompress
 */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif
#include "vaptvupt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    /* Read fuzzed input from stdin */
    size_t cap = 2 * 1024 * 1024; /* 2 MB max */
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return 1;

    size_t total = 0;
    while (total < cap) {
        ssize_t n = read(0, buf + total, cap - total);
        if (n <= 0) break;
        total += (size_t)n;
    }

    if (total < 16) { free(buf); return 0; } /* Too small for VV frame header */

    /* Allocate generous output buffer */
    size_t out_cap = 4 * 1024 * 1024; /* 4 MB */
    uint8_t *out = (uint8_t *)malloc(out_cap);
    if (!out) { free(buf); return 1; }

    /* Attempt decompression — this is the fuzz target */
    int64_t result = vv_decompress(buf, total, out, out_cap);
    (void)result; /* Don't care about return — we're looking for crashes */

    free(out);
    free(buf);
    return 0;
}
