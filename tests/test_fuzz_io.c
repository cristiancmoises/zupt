/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (c) 2026 Cristian Cezar Moisés */
#define _DEFAULT_SOURCE 1
#include "zupt.h"
#include "vaptvupt.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

ssize_t __real_read(int, void *, size_t);
ssize_t __real_write(int, const void *, size_t);
int __real_mkstemp(char *);
char *__real_mkdtemp(char *);
int64_t __real_vv_decompress(const uint8_t *, size_t, uint8_t *, size_t);
/* GNU ld --wrap needs external symbols, with prototypes on both sides. */
ssize_t __wrap_read(int, void *, size_t);
ssize_t __wrap_write(int, const void *, size_t);
int __wrap_mkstemp(char *);
char *__wrap_mkdtemp(char *);
int64_t __wrap_vv_decompress(const uint8_t *, size_t, uint8_t *, size_t);
#ifdef FUZZ_TEST_ARCHIVE
zupt_error_t __real_zupt_extract_archive(const char *, const char *, zupt_options_t *);
zupt_error_t __real_zupt_test_archive(const char *, zupt_options_t *);
zupt_error_t __real_zupt_list_archive(const char *, zupt_options_t *);
zupt_error_t __wrap_zupt_extract_archive(const char *, const char *, zupt_options_t *);
zupt_error_t __wrap_zupt_test_archive(const char *, zupt_options_t *);
zupt_error_t __wrap_zupt_list_archive(const char *, zupt_options_t *);
#endif

static int mode(const char *name)
{
    const char *selected = getenv("ZUPT_FUZZ_IO_MODE");
    return selected && !strcmp(selected, name);
}

ssize_t __wrap_read(int fd, void *buffer, size_t size)
{
    static int interrupted;
    if (fd == STDIN_FILENO && mode("read-eintr") && !interrupted++) {
        errno = EINTR;
        return -1;
    }
    if (fd == STDIN_FILENO && mode("read-short") && size > 7) size = 7;
    return __real_read(fd, buffer, size);
}

ssize_t __wrap_write(int fd, const void *buffer, size_t size)
{
    static int interrupted;
    if (mode("write-error")) { errno = ENOSPC; return -1; }
    if (mode("write-eintr") && !interrupted++) { errno = EINTR; return -1; }
    if (mode("write-short") && size > 7) size = 7;
    return __real_write(fd, buffer, size);
}

int __wrap_mkstemp(char *path)
{
    int result = __real_mkstemp(path);
    if (result >= 0) fprintf(stderr, "FUZZ-TEMP: %s\n", path);
    return result;
}

char *__wrap_mkdtemp(char *path)
{
    if (mode("directory-error")) { errno = ENOSPC; return NULL; }
    char *result = __real_mkdtemp(path);
    if (result) fprintf(stderr, "FUZZ-TEMP: %s\n", path);
    const char *sentinel = getenv("ZUPT_FUZZ_SENTINEL");
    if (result && sentinel) {
        char link_path[4096];
        int length = snprintf(link_path, sizeof(link_path), "%s/outside-link", path);
        if (length < 0 || (size_t)length >= sizeof(link_path) ||
            symlink(sentinel, link_path)) {
            rmdir(path);
            return NULL;
        }
    }
    return result;
}

int64_t __wrap_vv_decompress(const uint8_t *input, size_t size,
                           uint8_t *output, size_t capacity)
{
    int64_t result = __real_vv_decompress(input, size, output, capacity);
    fprintf(stderr, "FUZZ-TARGET: vv input=%zu result=%lld\n", size, (long long)result);
    return result;
}

#ifdef FUZZ_TEST_ARCHIVE
zupt_error_t __wrap_zupt_extract_archive(const char *path, const char *output,
                                        zupt_options_t *options)
{
    zupt_error_t result = __real_zupt_extract_archive(path, output, options);
    fprintf(stderr, "FUZZ-TARGET: extract result=%d\n", (int)result);
    return result;
}

zupt_error_t __wrap_zupt_test_archive(const char *path, zupt_options_t *options)
{
    zupt_error_t result = __real_zupt_test_archive(path, options);
    fprintf(stderr, "FUZZ-TARGET: test result=%d\n", (int)result);
    return result;
}

zupt_error_t __wrap_zupt_list_archive(const char *path, zupt_options_t *options)
{
    zupt_error_t result = __real_zupt_list_archive(path, options);
    fprintf(stderr, "FUZZ-TARGET: list result=%d\n", (int)result);
    return result;
}
#endif
