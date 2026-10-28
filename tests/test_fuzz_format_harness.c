/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (c) 2026 Cristian Cezar Moisés */
#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Record the exact bytes seen by this fixture, not the seed before mutation. */
static int capture_input(const char *archive) {
    const char *log_path = getenv("ZUPT_FUZZ_TEST_PATH_LOG");
    if (!log_path) return 0;
    const char *temp_root = getenv("TMPDIR");
    if (!temp_root || !*temp_root ||
        strncmp(archive, temp_root, strlen(temp_root)) ||
        archive[strlen(temp_root)] != '/') return -1;
    const char *leaf = strrchr(archive, '/');
    char directory[PATH_MAX], copy_path[PATH_MAX];
    size_t length = (size_t)(leaf - archive);
    if (length >= sizeof(directory)) return -1;
    memcpy(directory, archive, length);
    directory[length] = '\0';
    struct stat info;
    if (lstat(directory, &info) || !S_ISDIR(info.st_mode) ||
        (info.st_mode & 0777) != 0700 || lstat(archive, &info) ||
        !S_ISREG(info.st_mode) || (info.st_mode & 0777) != 0600) return -1;
    int written = snprintf(copy_path, sizeof(copy_path), "%s.input", log_path);
    if (written < 0 || (size_t)written >= sizeof(copy_path)) return -1;
    FILE *log = fopen(log_path, "a");
    if (!log) return -1;
    int failed = fprintf(log, "%s\n", archive) < 0;
    if (fclose(log)) failed = 1;
    if (failed) return -1;
    FILE *input = fopen(archive, "rb");
    if (!input) return -1;
    FILE *copy = fopen(copy_path, "wb");
    if (!copy) { fclose(input); return -1; }
    unsigned char bytes[4096];
    size_t size;
    while ((size = fread(bytes, 1, sizeof(bytes), input)) != 0)
        if (fwrite(bytes, 1, size, copy) != size) { failed = 1; break; }
    if (ferror(input)) failed = 1;
    if (fclose(input)) failed = 1;
    if (fclose(copy)) failed = 1;
    return failed ? -1 : 0;
}

/* A controlled child for testing the harness, not a replacement decoder. */
int main(int argc, char **argv) {
    const char *mode = getenv("ZUPT_FUZZ_TEST_MODE");
    if (!mode || argc != 3 || strcmp(argv[1], "list")) return 127;
    if (capture_input(argv[2])) {
        fputs("Fixture input is not private under TMPDIR or cannot be recorded\n", stderr);
        return 127;
    }
    if (!strcmp(mode, "accept")) return 0;
    if (!strcmp(mode, "reject")) return 1;
    if (!strcmp(mode, "remove-input")) return unlink(argv[2]) ? 127 : 0;
    if (!strcmp(mode, "extra-entry")) {
        char path[PATH_MAX];
        int length = snprintf(path, sizeof(path), "%s.extra", argv[2]);
        if (length < 0 || (size_t)length >= sizeof(path)) return 127;
        FILE *extra = fopen(path, "wb");
        if (!extra) return 127;
        int failed = fputs("owned fixture\n", extra) == EOF;
        if (fclose(extra)) failed = 1;
        return failed ? 127 : 0;
    }
    if (!strcmp(mode, "signal")) {
        raise(SIGTERM);
        return 127;
    }
    if (!strcmp(mode, "ubsan-real")) {
        volatile int numerator = 1, denominator = 0;
        return numerator / denominator;
    }
    if (!strcmp(mode, "binary-prefix")) {
        static const unsigned char prefix[] = {'x', 0, 'y', '\n'};
        if (fwrite(prefix, 1, sizeof(prefix), stderr) != sizeof(prefix)) return 127;
    }
    if (!strcmp(mode, "asan"))
        fputs("ERROR: AddressSanitizer: heap-buffer-overflow\n", stderr);
    else if (!strcmp(mode, "lsan"))
        fputs("ERROR: LeakSanitizer: detected memory leaks\n", stderr);
    else if (!strcmp(mode, "ubsan-name"))
        fputs("UndefinedBehaviorSanitizer: undefined-behavior\n", stderr);
    else if (!strcmp(mode, "too-much-output")) {
        for (unsigned i = 0; i < 65537; i++) fputc('x', stderr);
    } else
        fputs("fixture.c:1:1: runtime error: division by zero\n", stderr);
    return !strcmp(mode, "diagnostic-success") ? 0 : 1;
}
