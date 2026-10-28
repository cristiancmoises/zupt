/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "zuptsdk.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* Only temporary-file boundaries are replaced; archive processing is real. */
FILE *__real_fopen(const char *, const char *);
int __real_fclose(FILE *);
size_t __real_fwrite(const void *, size_t, size_t, FILE *);
FILE *__wrap_fopen(const char *, const char *);
FILE *__real_zupt_private_staging_open_new(const char *, int *);
FILE *__wrap_zupt_private_staging_open_new(const char *, int *);
int __wrap_fclose(FILE *);
size_t __wrap_fwrite(const void *, size_t, size_t, FILE *);

enum fault {
    DRAIN_CLOSE = 1,
    PUMP_CLOSE = 2,
    PUMP_READ = 4
};

static FILE *stage_file, *archive_file;
static unsigned faults, injected, opens, closes, oversized_writes;

struct read_fault {
    FILE *source;
    size_t remaining;
};

static ssize_t fault_read(void *cookie, char *buf, size_t size) {
    struct read_fault *s = cookie;
    if (!s->remaining) {
        injected |= PUMP_READ;
        errno = EIO;
        return -1;
    }
    if (size > s->remaining) size = s->remaining;
    size_t n = fread(buf, 1, size, s->source);
    s->remaining -= n;
    return (ssize_t)n;
}

static int fault_close(void *cookie) {
    struct read_fault *s = cookie;
    int rc = __real_fclose(s->source);
    free(s);
    return rc;
}

FILE *__wrap_fopen(const char *path, const char *mode) {
    FILE *f = __real_fopen(path, mode);
    if (!f) return NULL;
    if (strstr(path, "/zsdk_arc_") && strcmp(mode, "rb") == 0) {
        if (faults & PUMP_READ) {
            struct read_fault *s = malloc(sizeof(*s));
            if (!s) { __real_fclose(f); return NULL; }
            s->source = f;
            s->remaining = 17;
            cookie_io_functions_t io = {fault_read, NULL, NULL, fault_close};
            f = fopencookie(s, "r", io);
            if (!f) { fault_close(s); return NULL; }
        }
        archive_file = f;
        ++opens;
    }
    return f;
}

FILE *__wrap_zupt_private_staging_open_new(const char *path, int *created) {
    FILE *f = __real_zupt_private_staging_open_new(path, created);
    if (f) { stage_file = f; ++opens; }
    return f;
}

int __wrap_fclose(FILE *f) {
    unsigned fault = 0;
    if (f == stage_file) {
        stage_file = NULL;
        ++closes;
        fault = DRAIN_CLOSE;
    }
    if (f == archive_file) {
        archive_file = NULL;
        ++closes;
        fault = PUMP_CLOSE;
    }
    /* fclose releases the stream even when its final flush reports failure. */
    int rc = __real_fclose(f);
    if (faults & fault) {
        injected |= fault;
        errno = EIO;
        return EOF;
    }
    return rc;
}

size_t __wrap_fwrite(const void *buf, size_t size, size_t count, FILE *f) {
    /* Trap oversized writes before libc could read beyond the input buffer.
     * Each case requires the helper to reject the count before reaching here. */
    if (f == stage_file && size == 1 && count > 65536) {
        ++oversized_writes;
        errno = EINVAL;
        return 0;
    }
    return __real_fwrite(buf, size, count, f);
}

struct input_state {
    const uint8_t *data;
    size_t size, offset;
    int invalid_return;
};

struct output_state {
    uint8_t data[65536];
    size_t size;
    int invalid_return;
};

static int64_t input_cb(void *userdata, uint8_t *buf, size_t capacity) {
    struct input_state *s = userdata;
    if (s->invalid_return == 1) return (int64_t)capacity + 1;
    if (s->invalid_return == 2) return INT64_MAX;
    if (s->invalid_return == 3 && s->offset) return -1;
    size_t n = s->size - s->offset;
    if (n > capacity) n = capacity;
    if (n > 7) n = 7;
    if (n) memcpy(buf, s->data + s->offset, n);
    s->offset += n;
    return (int64_t)n;
}

static int64_t output_cb(void *userdata, const uint8_t *buf, size_t size) {
    struct output_state *s = userdata;
    if (s->invalid_return == 1) return -1;
    if (s->invalid_return == 2) return (int64_t)size - 1;
    if (size > sizeof(s->data) - s->size) return -1;
    if (size) memcpy(s->data + s->size, buf, size);
    s->size += size;
    return (int64_t)size;
}

static int run_case(unsigned requested, int input_error, int output_error,
                    int decompress) {
    static const uint8_t payload[] = "stream error regression payload\n";
    struct input_state input = {payload, sizeof(payload) - 1, 0, input_error};
    struct output_state output = {{0}, 0, output_error};
    int rc, failed = 0;
    faults = requested;
    injected = opens = closes = oversized_writes = 0;
    stage_file = archive_file = NULL;

    if (decompress)
        rc = zuptsdk_decompress_stream(NULL, input_cb, &input, output_cb,
                                       &output, NULL, NULL);
    else
        rc = zuptsdk_compress_stream(NULL, NULL, input_cb, &input, "input.txt",
                                     input.size, output_cb, &output, NULL, NULL);
    int expected = requested || input_error || output_error
        ? ZUPTSDK_ERR_IO : ZUPTSDK_OK;
    if (rc != expected || injected != requested || oversized_writes ||
        opens != closes || stage_file || archive_file) {
        fprintf(stderr, "FAIL: rc=%d expected=%d faults=%u/%u oversized=%u "
                "closed=%u/%u (%s)\n", rc, expected, injected, requested,
                oversized_writes, closes, opens, zuptsdk_last_error_detail());
        failed = 1;
    }
    if (requested == PUMP_READ && output.size != 17) failed = 1;
    if (input_error && output.size) failed = 1;
    if ((requested & DRAIN_CLOSE) && input_error == 3 &&
        !strstr(zuptsdk_last_error_detail(), "read callback returned -1"))
        failed = 1;
    if ((requested & PUMP_CLOSE) && output_error &&
        !strstr(zuptsdk_last_error_detail(), "write callback short"))
        failed = 1;
    if (expected == ZUPTSDK_OK && !failed) {
        struct input_state archive = {output.data, output.size, 0, 0};
        struct output_state restored = {{0}, 0, 0};
        rc = zuptsdk_decompress_stream(NULL, input_cb, &archive, output_cb,
                                       &restored, NULL, NULL);
        if (rc != ZUPTSDK_OK || restored.size != input.size ||
            memcmp(restored.data, payload, input.size) != 0 || opens != closes)
            failed = 1;
    }
    return failed;
}

int main(void) {
    static const struct {
        const char *name;
        unsigned requested;
        int input_error, output_error, decompress;
    } cases[] = {
        {"byte-exact stream roundtrip", 0, 0, 0, 0},
        {"drain close failure", DRAIN_CLOSE, 0, 0, 0},
        {"pump close failure", PUMP_CLOSE, 0, 0, 0},
        {"read error after a delivered prefix", PUMP_READ, 0, 0, 0},
        {"negative read callback", 0, 3, 0, 0},
        {"short write callback", 0, 0, 2, 0},
        {"negative write callback", 0, 0, 1, 0},
        {"read error precedes close error", DRAIN_CLOSE, 3, 0, 0},
        {"write error precedes close error", PUMP_CLOSE, 0, 1, 0},
        {"compress read exceeds capacity", 0, 1, 0, 0},
        {"compress read returns INT64_MAX", 0, 2, 0, 0},
        {"decompress read exceeds capacity", 0, 1, 0, 1},
        {"decompress read returns INT64_MAX", 0, 2, 0, 1}
    };
    unsigned failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int failed = run_case(cases[i].requested, cases[i].input_error,
                               cases[i].output_error, cases[i].decompress);
        fprintf(stderr, "%s: %s\n", failed ? "FAIL" : "PASS", cases[i].name);
        failures += (unsigned)failed;
    }
    fprintf(stderr, "Stream tests: %zu cases, %u failures\n",
            sizeof(cases) / sizeof(cases[0]), failures);
    return failures ? 1 : 0;
}
