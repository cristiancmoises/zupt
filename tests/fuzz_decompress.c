/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 * ZUPT v2.0.0 — AFL++ Fuzzing Harness: Archive Decompression
 * Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-or-later
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
#define _XOPEN_SOURCE 700
#include "zupt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ftw.h>

static int remove_output(const char *path, const struct stat *info,
                         int type, struct FTW *walk)
{
    (void)info;
    (void)type;
    (void)walk;
    return remove(path);
}

int main(void) {
    /* Read entire stdin into memory */
    size_t cap = 4 * 1024 * 1024; /* 4 MB max fuzz input */
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return 1;

    size_t total = 0;
    while (total < cap) {
        ssize_t n = read(0, buf + total, cap - total);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { perror("fuzz input read"); free(buf); return 1; }
        if (n == 0) break;
        total += (size_t)n;
    }

    if (total < 64) { free(buf); return 0; } /* Too small for a valid archive */

    /* Write to temp file (zupt_extract_archive needs a file path) */
    char tmp_arc[] = "/tmp/zupt_fuzz_XXXXXX";
    int fd = mkstemp(tmp_arc);
    if (fd < 0) { free(buf); return 1; }
    size_t written = 0;
    while (written < total) {
        ssize_t n = write(fd, buf + written, total - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            perror("fuzz archive write");
            close(fd);
            unlink(tmp_arc);
            free(buf);
            return 1;
        }
        written += (size_t)n;
    }
    if (close(fd)) { perror("fuzz archive close"); unlink(tmp_arc); free(buf); return 1; }
    free(buf);

    /* Attempt extraction — this is where crashes happen */
    zupt_options_t opts;
    zupt_default_options(&opts);
    opts.quiet = 1;

    char tmp_out[] = "/tmp/zupt_fuzz_out_XXXXXX";
    if (!mkdtemp(tmp_out)) {
        perror("fuzz output directory");
        unlink(tmp_arc);
        return 1;
    }

    zupt_extract_archive(tmp_arc, tmp_out, &opts);

    /* Also try test (integrity check without extraction) */
    zupt_test_archive(tmp_arc, &opts);

    /* Also try list */
    zupt_list_archive(tmp_arc, &opts);

    /* Cleanup */
    int failed = unlink(tmp_arc) != 0;
    /* Each invocation owns this mkdtemp tree. Remove entries after children,
     * and unlink symlinks themselves rather than traversing their targets. */
    if (nftw(tmp_out, remove_output, 16, FTW_DEPTH | FTW_PHYS)) failed = 1;
    if (failed) perror("fuzz temporary cleanup");
    return failed;
}
