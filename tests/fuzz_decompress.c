/*
 * Zupt v2.0.0 — AFL++ Fuzzing Harness: Archive Decompression
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Reads a fuzzed .zupt archive from stdin, attempts to extract it.
 * Catches crashes, buffer overflows, and undefined behavior.
 *
 * Build:
 *   afl-clang-fast -fsanitize=address,undefined -g -O1 \
 *     -Iinclude -Isrc $(SOURCES) tests/fuzz_decompress.c \
 *     -lm -lpthread -o fuzz_decompress
 *
 * Run:
 *   mkdir -p corpus findings
 *   # Generate seed corpus:
 *   ./zupt compress /tmp/fuzz_seed.zupt /path/to/small/testfile
 *   cp /tmp/fuzz_seed.zupt corpus/
 *   afl-fuzz -i corpus -o findings -- ./fuzz_decompress
 */
#include "zupt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    /* Read entire stdin into memory */
    size_t cap = 4 * 1024 * 1024; /* 4 MB max fuzz input */
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return 1;

    size_t total = 0;
    while (total < cap) {
        ssize_t n = read(0, buf + total, cap - total);
        if (n <= 0) break;
        total += (size_t)n;
    }

    if (total < 64) { free(buf); return 0; } /* Too small for a valid archive */

    /* Write to temp file (zupt_extract_archive needs a file path) */
    char tmp_arc[] = "/tmp/zupt_fuzz_XXXXXX";
    int fd = mkstemp(tmp_arc);
    if (fd < 0) { free(buf); return 1; }
    write(fd, buf, total);
    close(fd);
    free(buf);

    /* Attempt extraction — this is where crashes happen */
    zupt_options_t opts;
    zupt_default_options(&opts);
    opts.quiet = 1;

    char tmp_out[] = "/tmp/zupt_fuzz_out_XXXXXX";
    mkdtemp(tmp_out);

    zupt_extract_archive(tmp_arc, tmp_out, &opts);

    /* Also try test (integrity check without extraction) */
    zupt_test_archive(tmp_arc, &opts);

    /* Also try list */
    zupt_list_archive(tmp_arc, &opts);

    /* Cleanup */
    unlink(tmp_arc);
    /* Note: not recursively removing tmp_out — AFL runs are ephemeral */

    return 0;
}
