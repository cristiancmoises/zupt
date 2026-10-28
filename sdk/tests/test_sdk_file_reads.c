/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "zuptsdk.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

FILE *__real_fopen(const char *, const char *);
int __real_fseek(FILE *, long, int);
long __real_ftell(FILE *);
size_t __real_fread(void *, size_t, size_t, FILE *);
int __real_ferror(FILE *);
int __real_fclose(FILE *);
FILE *__wrap_fopen(const char *, const char *);
int __wrap_fseek(FILE *, long, int);
long __wrap_ftell(FILE *);
size_t __wrap_fread(void *, size_t, size_t, FILE *);
int __wrap_ferror(FILE *);
int __wrap_fclose(FILE *);

enum fault {
    NO_FAULT, OPEN_ERROR, SEEK_END_ERROR, TELL_ERROR, SEEK_SET_ERROR,
    SHORT_READ, FULL_READ_ERROR, CLOSE_ERROR, ALLOCATION_ERROR,
    SHORT_READ_CLOSE_ERROR, ALLOCATION_CLOSE_ERROR
};
enum caller { COMPRESS_FILES, COMPRESS_BUFFER, EXTRACT_BUFFER,
              DECOMPRESS_ARCHIVE, DECOMPRESS_PLAIN };

static enum fault fault;
static FILE *target;
static int armed, want_plain, selected, injected, fatal, operations_after_error;
static int target_opened, target_closed, read_seen, after_end, slurp_allocations;
static int refused_size, allocation_failed, dirty_frees;
static int close_failed;
static void *slurp_buffer;

struct allocation { void *ptr; size_t size; };
static struct allocation allocations[32];
static size_t live_allocations;

/* Hooks are installed once before using the SDK. No context changes them. */
static void *test_malloc(void *userdata, size_t size) {
    (void)userdata;
    if (armed && target && after_end) {
        ++slurp_allocations;
        if (fatal) ++operations_after_error;
        if (fault == ALLOCATION_ERROR || fault == ALLOCATION_CLOSE_ERROR) {
            injected = allocation_failed = 1;
            errno = ENOMEM;
            return NULL;
        }
    }
    /* malloc(0) is allowed to fail. Empty extracts must not depend on it. */
    if (!size) return NULL;
    if (size > 16 * 1024 * 1024) { refused_size = 1; return NULL; }
    void *ptr = malloc(size);
    if (!ptr) return NULL;
    memset(ptr, 0xa5, size);
    size_t slot = 0;
    while (slot < sizeof(allocations) / sizeof(allocations[0]) &&
           allocations[slot].ptr) ++slot;
    if (slot == sizeof(allocations) / sizeof(allocations[0])) abort();
    allocations[slot].ptr = ptr;
    allocations[slot].size = size;
    ++live_allocations;
    if (armed && target && after_end) slurp_buffer = ptr;
    return ptr;
}

static void test_free(void *userdata, void *ptr) {
    (void)userdata;
    if (!ptr) return;
    size_t slot = 0;
    while (slot < sizeof(allocations) / sizeof(allocations[0]) &&
           allocations[slot].ptr != ptr) ++slot;
    if (slot == sizeof(allocations) / sizeof(allocations[0])) abort();
    if (ptr == slurp_buffer && read_seen && fault != NO_FAULT &&
        fault != ALLOCATION_ERROR && fault != ALLOCATION_CLOSE_ERROR) {
        const unsigned char *bytes = ptr;
        for (size_t i = 0; i < allocations[slot].size; ++i)
            if (bytes[i]) { ++dirty_frees; break; }
    }
    if (ptr == slurp_buffer) slurp_buffer = NULL;
    allocations[slot].ptr = NULL;
    --live_allocations;
    free(ptr);
}

static void *test_realloc(void *userdata, void *ptr, size_t size) {
    if (!ptr) return test_malloc(userdata, size);
    if (!size) { test_free(userdata, ptr); return NULL; }
    size_t slot = 0;
    while (slot < sizeof(allocations) / sizeof(allocations[0]) &&
           allocations[slot].ptr != ptr) ++slot;
    if (slot == sizeof(allocations) / sizeof(allocations[0])) abort();
    void *next = test_malloc(userdata, size);
    if (!next) return NULL;
    size_t copied = allocations[slot].size;
    if (copied > size) copied = size;
    memcpy(next, ptr, copied);
    test_free(userdata, ptr);
    return next;
}

FILE *__wrap_fopen(const char *path, const char *mode) {
    int match = armed && !selected && strcmp(mode, "rb") == 0 &&
        (want_plain ? strstr(path, "/zsdk_x_") != NULL
                    : strstr(path, "/zsdk_arc_") != NULL);
    if (match) {
        selected = 1;
        if (fault == OPEN_ERROR) { injected = 1; errno = EIO; return NULL; }
    }
    FILE *f = __real_fopen(path, mode);
    if (match && f) { target = f; ++target_opened; }
    return f;
}

int __wrap_fseek(FILE *f, long offset, int whence) {
    if (f == target) {
        if (fatal) ++operations_after_error;
        if (whence == SEEK_END) after_end = 1;
        if ((fault == SEEK_END_ERROR && whence == SEEK_END) ||
            (fault == SEEK_SET_ERROR && whence == SEEK_SET)) {
            injected = fatal = 1;
            errno = EIO;
            return -1;
        }
    }
    return __real_fseek(f, offset, whence);
}

long __wrap_ftell(FILE *f) {
    if (f == target) {
        if (fatal) ++operations_after_error;
        if (fault == TELL_ERROR) {
            injected = fatal = 1;
            errno = EIO;
            return -1;
        }
    }
    return __real_ftell(f);
}

size_t __wrap_fread(void *buf, size_t size, size_t count, FILE *f) {
    if (f == target) {
        if (fatal) ++operations_after_error;
        read_seen = 1;
        if ((fault == SHORT_READ || fault == SHORT_READ_CLOSE_ERROR) && count) {
            injected = 1;
            size_t got = __real_fread(buf, size, count - 1, f);
            if (fault == SHORT_READ_CLOSE_ERROR) errno = EPIPE;
            return got;
        }
        if (fault == FULL_READ_ERROR) injected = 1;
    }
    return __real_fread(buf, size, count, f);
}

int __wrap_ferror(FILE *f) {
    if (f == target && read_seen && fault == FULL_READ_ERROR) return 1;
    return __real_ferror(f);
}

int __wrap_fclose(FILE *f) {
    int match = f == target;
    if (match) { target = NULL; ++target_closed; }
    int rc = __real_fclose(f);
    if (match && (fault == CLOSE_ERROR || fault == SHORT_READ_CLOSE_ERROR ||
                  fault == ALLOCATION_CLOSE_ERROR)) {
        close_failed = 1;
        injected = 1;
        errno = fault == CLOSE_ERROR ? EIO : EBADF;
        return EOF;
    }
    return rc;
}

struct input { const uint8_t *data; size_t size, offset; };
struct output { uint8_t data[128]; size_t size; unsigned calls; };

static int64_t read_cb(void *userdata, uint8_t *buf, size_t capacity) {
    struct input *input = userdata;
    size_t n = input->size - input->offset;
    if (n > capacity) n = capacity;
    if (n) memcpy(buf, input->data + input->offset, n);
    input->offset += n;
    return (int64_t)n;
}

static int64_t write_cb(void *userdata, const uint8_t *buf, size_t size) {
    struct output *output = userdata;
    ++output->calls;
    if (size > sizeof(output->data) - output->size) return -1;
    if (size) memcpy(output->data + output->size, buf, size);
    output->size += size;
    return (int64_t)size;
}

static const uint8_t payload[] = "file read regression payload\n";
static uint8_t *archive, *empty_archive;
static size_t archive_size, empty_archive_size;
static char input_path[256];

static int run_case(enum caller caller, enum fault requested, int empty) {
    uint8_t sentinel = 0x7b;
    uint8_t *out = &sentinel;
    size_t out_size = 987;
    const uint8_t *source = empty ? empty_archive : archive;
    size_t source_size = empty ? empty_archive_size : archive_size;
    size_t baseline_allocations = live_allocations;
    struct input input = {source, source_size, 0};
    struct output output = {{0}, 0, 0};
    fault = requested;
    target = NULL;
    selected = injected = fatal = operations_after_error = 0;
    target_opened = target_closed = read_seen = after_end = 0;
    slurp_allocations = refused_size = allocation_failed = dirty_frees = 0;
    close_failed = 0;
    slurp_buffer = NULL;
    want_plain = caller == EXTRACT_BUFFER || caller == DECOMPRESS_PLAIN;
    armed = 1;
    int rc;
    if (caller == COMPRESS_FILES) {
        const char *paths[] = {input_path};
        rc = zuptsdk_compress_files(NULL, NULL, paths, 1, NULL, NULL,
                                    &out, &out_size);
    } else if (caller == COMPRESS_BUFFER) {
        rc = zuptsdk_compress_buffer(NULL, NULL, "payload.txt", payload,
                                     sizeof(payload) - 1, NULL, NULL,
                                     &out, &out_size);
    } else if (caller == EXTRACT_BUFFER) {
        rc = zuptsdk_extract_buffer(NULL, source, source_size, NULL, NULL,
                                    &out, &out_size);
    } else {
        rc = zuptsdk_decompress_stream(NULL, read_cb, &input, write_cb,
                                       &output, NULL, NULL);
    }
    armed = 0;
    int expected = requested == NO_FAULT ? ZUPTSDK_OK :
        (requested == ALLOCATION_ERROR || requested == ALLOCATION_CLOSE_ERROR)
        ? ZUPTSDK_ERR_NO_MEMORY : ZUPTSDK_ERR_IO;
    int failed = rc != expected || !selected ||
        target_opened != target_closed || target || operations_after_error ||
        refused_size || dirty_frees ||
        (requested != NO_FAULT && !injected);
    if (requested != NO_FAULT &&
        (out != &sentinel || out_size != 987 || output.calls)) failed = 1;
    if (requested == SHORT_READ_CLOSE_ERROR &&
        (!close_failed || !strstr(zuptsdk_last_error_detail(), strerror(EPIPE)) ||
         strstr(zuptsdk_last_error_detail(), strerror(EBADF))))
        failed = 1;
    if (requested == ALLOCATION_CLOSE_ERROR &&
        (!allocation_failed || !close_failed ||
         !strstr(zuptsdk_last_error_detail(), strerror(ENOMEM)) ||
         strstr(zuptsdk_last_error_detail(), strerror(EBADF))))
        failed = 1;
    if (requested == NO_FAULT && caller <= COMPRESS_BUFFER &&
        (out == &sentinel || !out_size)) failed = 1;
    if (requested == NO_FAULT && caller <= COMPRESS_BUFFER &&
        out != &sentinel && out_size) {
        uint8_t *restored = NULL;
        size_t restored_size = 0;
        int restored_rc = zuptsdk_extract_buffer(NULL, out, out_size,
            NULL, NULL, &restored, &restored_size);
        if (restored_rc || restored_size != sizeof(payload) - 1 ||
            !restored || memcmp(restored, payload, sizeof(payload) - 1))
            failed = 1;
        zuptsdk_free(restored);
    }
    if (requested == NO_FAULT && caller == EXTRACT_BUFFER &&
        (out == &sentinel || out_size != (empty ? 0 : sizeof(payload) - 1) ||
         (!empty && memcmp(out, payload, sizeof(payload) - 1)))) failed = 1;
    if (requested == NO_FAULT && caller >= DECOMPRESS_ARCHIVE &&
        (output.size != (empty ? 0 : sizeof(payload) - 1) ||
         (!empty && memcmp(output.data, payload, sizeof(payload) - 1)))) failed = 1;
    if (out != &sentinel) zuptsdk_free(out);
    if (live_allocations != baseline_allocations) failed = 1;
    if (failed) fprintf(stderr,
        "  rc=%d want=%d selected=%d injected=%d closed=%d/%d after=%d "
        "slurp_allocs=%d large=%d dirty=%d live=%zu/%zu (%s)\n",
        rc, expected, selected, injected, target_closed, target_opened,
        operations_after_error, slurp_allocations, refused_size, dirty_frees,
        live_allocations, baseline_allocations, zuptsdk_last_error_detail());
    return failed;
}

int main(void) {
    zuptsdk_allocator_t allocator = {test_malloc, test_free, test_realloc, NULL};
    if (zuptsdk_set_allocator(&allocator) != ZUPTSDK_OK) {
        fprintf(stderr, "allocator setup failed\n"); return 2;
    }
    char workspace[] = "/tmp/zupt-sdk-file-read.XXXXXXXX";
    if (!mkdtemp(workspace) || setenv("TMPDIR", workspace, 1)) {
        perror("fixture workspace"); return 2;
    }
    snprintf(input_path, sizeof(input_path), "%s/input.txt", workspace);
    FILE *f = fopen(input_path, "wb");
    if (!f) { perror("fixture file"); return 2; }
    size_t wrote = fwrite(payload, 1, sizeof(payload) - 1, f);
    int close_rc = fclose(f);
    if (wrote != sizeof(payload) - 1 || close_rc) {
        perror("fixture write/close"); return 2;
    }
    int setup_rc = zuptsdk_compress_buffer(NULL, NULL, "payload.txt", payload,
            sizeof(payload) - 1, NULL, NULL, &archive, &archive_size);
    if (setup_rc) {
        fprintf(stderr, "fixture archive rc=%d (%s)\n", setup_rc,
                zuptsdk_last_error_detail());
        return 2;
    }
    setup_rc = zuptsdk_compress_buffer(NULL, NULL, "empty.txt", payload, 0,
            NULL, NULL, &empty_archive, &empty_archive_size);
    if (setup_rc) {
        fprintf(stderr, "empty fixture archive rc=%d (%s)\n", setup_rc,
                zuptsdk_last_error_detail());
        return 2;
    }
    static const char *const callers[] = {"compress_files", "compress_buffer",
        "extract_buffer", "decompress_stream/archive", "decompress_stream/plain"};
    static const char *const faults[] = {"roundtrip", "open failure",
        "seek end failure", "negative tell", "seek start failure",
        "short read", "full read with error", "close failure", "allocation failure",
        "read error precedes close error", "allocation error precedes close error"};
    unsigned failures = 0, cases = 0;
    for (int caller = COMPRESS_FILES; caller <= DECOMPRESS_PLAIN; ++caller) {
        for (int requested = NO_FAULT; requested <= ALLOCATION_CLOSE_ERROR; ++requested) {
            int failed = run_case((enum caller)caller, (enum fault)requested, 0);
            fprintf(stderr, "%s: %s: %s\n", failed ? "FAIL" : "PASS",
                    callers[caller], faults[requested]);
            failures += (unsigned)failed;
            ++cases;
        }
    }
    for (int caller = EXTRACT_BUFFER; caller <= DECOMPRESS_PLAIN; ++caller) {
        int failed = run_case((enum caller)caller, NO_FAULT, 1);
        fprintf(stderr, "%s: %s: empty file with malloc(0) returning NULL\n",
                failed ? "FAIL" : "PASS", callers[caller]);
        failures += (unsigned)failed;
        ++cases;
    }
    slurp_buffer = NULL;
    zuptsdk_free(archive);
    zuptsdk_free(empty_archive);
    if (live_allocations) ++failures;
    unlink(input_path);
    if (rmdir(workspace)) { perror("remove fixture workspace"); ++failures; }
    fprintf(stderr, "File-read tests: %u cases, %u failures\n", cases, failures);
    return failures ? 1 : 0;
}
