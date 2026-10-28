/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "zuptsdk.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

FILE *__real_fopen(const char *, const char *);
int __real_fclose(FILE *);
size_t __real_fread(void *, size_t, size_t, FILE *);
size_t __real_fwrite(const void *, size_t, size_t, FILE *);
FILE *__wrap_fopen(const char *, const char *);
int __wrap_fclose(FILE *);
size_t __wrap_fread(void *, size_t, size_t, FILE *);
size_t __wrap_fwrite(const void *, size_t, size_t, FILE *);

enum operation { SAVE_PRIVATE, SAVE_PUBLIC, COMPRESS_STREAM };
enum fault { NORMAL, READ_ERROR, READ_CLOSE_ERROR, READ_SINK_ERROR, EOF_CLOSE_ERROR,
             READ_SHORT_SINK_ERROR, READ_CALLBACK_ERROR, READ_CALLBACK_SINK_ERROR };
static enum operation operation;
static enum fault fault;
static int armed, opened, closed, after_error, after_eof, sink_failed, close_failed;
static FILE *target;
static struct { FILE *source; size_t remaining; int failed; } cookie;
static uint8_t read_prefix[17];
static size_t read_prefix_size;

static int inject_read_error(void) {
    return fault != NORMAL && fault != EOF_CLOSE_ERROR;
}

static ssize_t cookie_read(void *unused, char *buf, size_t size) {
    (void)unused;
    if (!cookie.remaining) {
        cookie.failed = 1;
        errno = EPIPE;
        return -1;
    }
    if (size > cookie.remaining) size = cookie.remaining;
    size_t got = __real_fread(buf, 1, size, cookie.source);
    cookie.remaining -= got;
    if (got > sizeof(read_prefix) - read_prefix_size) return -1;
    memcpy(read_prefix + read_prefix_size, buf, got);
    read_prefix_size += got;
    return (ssize_t)got;
}

static int cookie_close(void *unused) {
    (void)unused;
    int rc = __real_fclose(cookie.source);
    cookie.source = NULL;
    return rc;
}

FILE *__wrap_fopen(const char *path, const char *mode) {
    FILE *f = __real_fopen(path, mode);
    const char *prefix = operation == SAVE_PRIVATE ? "/zsdk_priv_" :
                         operation == SAVE_PUBLIC ? "/zsdk_pub_" : "/zsdk_arc_";
    if (!f || !armed || opened || strcmp(mode, "rb") || !strstr(path, prefix))
        return f;
    if (inject_read_error()) {
        cookie.source = f;
        cookie.remaining = 17;
        cookie_io_functions_t io = {cookie_read, NULL, NULL, cookie_close};
        f = fopencookie(NULL, "r", io);
        if (!f) { cookie_close(NULL); return NULL; }
    }
    target = f;
    ++opened;
    return f;
}

size_t __wrap_fread(void *buf, size_t size, size_t count, FILE *f) {
    if (f == target) {
        if (ferror(f)) ++after_error;
        if (feof(f)) ++after_eof;
    }
    return __real_fread(buf, size, count, f);
}

size_t __wrap_fwrite(const void *buf, size_t size, size_t count, FILE *f) {
    if (armed && operation != COMPRESS_STREAM && cookie.failed &&
        fault == READ_SINK_ERROR) {
        ++sink_failed;
        errno = ENOSPC;
        return 0;
    }
    return __real_fwrite(buf, size, count, f);
}

int __wrap_fclose(FILE *f) {
    int selected = f == target;
    if (selected) { target = NULL; ++closed; }
    int rc = __real_fclose(f);
    if (selected && (fault == READ_CLOSE_ERROR || fault == EOF_CLOSE_ERROR)) {
        ++close_failed;
        errno = EBADF;
        return EOF;
    }
    return rc;
}

static uint8_t payload[70000], output[131072];
static size_t input_offset, output_size;
static int64_t input_cb(void *unused, uint8_t *buf, size_t capacity) {
    (void)unused;
    size_t n = sizeof(payload) - input_offset;
    if (n > capacity) n = capacity;
    if (n) memcpy(buf, payload + input_offset, n);
    input_offset += n;
    return (int64_t)n;
}

static int64_t output_cb(void *unused, const uint8_t *buf, size_t size) {
    (void)unused;
    if (size > sizeof(output) - output_size) return -1;
    size_t delivered = fault == READ_SHORT_SINK_ERROR ? size / 2 : size;
    memcpy(output + output_size, buf, delivered);
    output_size += delivered;
    if (fault == READ_CALLBACK_ERROR || fault == READ_CALLBACK_SINK_ERROR) {
        /* A callback may make another SDK call before its caller reports I/O. */
        if (zuptsdk_options_create(NULL) != ZUPTSDK_ERR_INVALID_ARG) return -1;
    }
    if (fault == READ_SINK_ERROR || fault == READ_CALLBACK_SINK_ERROR) {
        ++sink_failed;
        errno = ENOSPC;
        return -1;
    }
    if (fault == READ_SHORT_SINK_ERROR) {
        ++sink_failed;
        errno = ENOSPC;
    }
    return (int64_t)delivered;
}

static const uint8_t sentinel[] = "preserve existing destination\n";

static size_t read_file(const char *path, uint8_t *buf, size_t capacity) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, capacity, f);
    int valid = !ferror(f) && feof(f);
    if (fclose(f) != 0) valid = 0;
    return valid ? n : 0;
}

static int run_case(zuptsdk_keypair_t *kp, zuptsdk_options_t *opts,
                    enum operation requested, enum fault requested_fault,
                    const char *destination, const uint8_t *expected, size_t expected_size) {
    struct stat before, after;
    FILE *f = fopen(destination, "wb");
    if (!f) return 1;
    size_t wrote = fwrite(sentinel, 1, sizeof(sentinel) - 1, f);
    int close_rc = fclose(f);
    if (wrote != sizeof(sentinel) - 1 || close_rc || stat(destination, &before))
        return 1;
    operation = requested;
    fault = requested_fault;
    target = cookie.source = NULL;
    cookie.failed = opened = closed = after_error = after_eof = 0;
    sink_failed = close_failed = 0;
    read_prefix_size = 0;
    input_offset = output_size = 0;
    armed = 1;
    int rc = operation == SAVE_PRIVATE ? zuptsdk_keypair_save_private(kp, destination) :
             operation == SAVE_PUBLIC ? zuptsdk_keypair_save_public(kp, destination) :
             zuptsdk_compress_stream(NULL, opts, input_cb, NULL, "payload.bin",
                                      sizeof(payload), output_cb, NULL, NULL, NULL);
    armed = 0;
    int failed = rc != (fault == NORMAL ? ZUPTSDK_OK : ZUPTSDK_ERR_IO) ||
        opened != 1 || closed != 1 || target || cookie.source || after_error || after_eof;
    if (inject_read_error()) {
        if (!cookie.failed || !strstr(zuptsdk_last_error_detail(), strerror(EPIPE)) ||
            !strstr(zuptsdk_last_error_detail(), "read "))
            failed = 1;
        if (operation == COMPRESS_STREAM) {
            size_t delivered = fault == READ_SHORT_SINK_ERROR ? 8 : 17;
            if (read_prefix_size != 17 || output_size != delivered ||
                memcmp(output, read_prefix, delivered)) failed = 1;
        }
    }
    if (fault == READ_CLOSE_ERROR || fault == EOF_CLOSE_ERROR)
        if (close_failed != 1) failed = 1;
    if ((fault == READ_SINK_ERROR || fault == READ_SHORT_SINK_ERROR ||
         fault == READ_CALLBACK_SINK_ERROR) && sink_failed != 1) failed = 1;
    if (operation == COMPRESS_STREAM && fault == NORMAL) {
        uint8_t *restored = NULL;
        size_t restored_size = 0;
        int status = zuptsdk_extract_buffer(NULL, output, output_size,
                                            NULL, NULL, &restored, &restored_size);
        if (status || !restored || restored_size != sizeof(payload) ||
            memcmp(restored, payload, sizeof(payload))) failed = 1;
        zuptsdk_free(restored);
        if (output_size <= 65536) failed = 1;
    }
    uint8_t observed[4096];
    if (operation != COMPRESS_STREAM) {
        size_t n = read_file(destination, observed, sizeof(observed));
        if (fault == NORMAL) {
            if (n != expected_size || memcmp(observed, expected, expected_size))
                failed = 1;
        } else if (stat(destination, &after) || n != sizeof(sentinel) - 1 ||
                   memcmp(observed, sentinel, sizeof(sentinel) - 1) ||
                   before.st_dev != after.st_dev || before.st_ino != after.st_ino)
            failed = 1;
    }
    if (failed) fprintf(stderr, "  rc=%d opened=%d closed=%d after_error=%d "
        "after_eof=%d sink_failed=%d close_failed=%d (%s)\n", rc, opened, closed,
        after_error, after_eof, sink_failed, close_failed, zuptsdk_last_error_detail());
    unlink(destination);
    return failed;
}

int main(void) {
    char workspace[] = "/tmp/zupt-sdk-read-stop.XXXXXXXX";
    if (!mkdtemp(workspace) || setenv("TMPDIR", workspace, 1)) return 2;
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)(i * 131 + 17);
    zuptsdk_keypair_t *kp = NULL;
    zuptsdk_options_t *opts = NULL;
    char path[256];
    uint8_t private_key[4096], public_key[4096];
    if (zuptsdk_keypair_generate(NULL, &kp) || zuptsdk_options_create(&opts) ||
        zuptsdk_options_set_codec(opts, ZUPTSDK_CODEC_STORE)) return 2;
    snprintf(path, sizeof(path), "%s/private-copy", workspace);
    if (zuptsdk_keypair_save_private(kp, path)) return 2;
    size_t private_size = read_file(path, private_key, sizeof(private_key));
    unlink(path);
    snprintf(path, sizeof(path), "%s/public-copy", workspace);
    if (zuptsdk_keypair_save_public(kp, path)) return 2;
    size_t public_size = read_file(path, public_key, sizeof(public_key));
    unlink(path);
    if (private_size != 3664 || public_size != 1232) return 2;
    static const char *const names[] = {"save-private", "save-public", "stream-pump"};
    static const char *const faults[] = {"normal EOF", "partial read error",
        "read then close error", "read then sink error", "EOF then close error",
        "read then short sink", "read then nested SDK error",
        "read then nested SDK and sink errors"};
    unsigned failures = 0, cases = 0;
    for (int which = SAVE_PRIVATE; which <= COMPRESS_STREAM; ++which) {
        int last_fault = which == COMPRESS_STREAM ? READ_CALLBACK_SINK_ERROR : EOF_CLOSE_ERROR;
        for (int mode = NORMAL; mode <= last_fault; ++mode) {
            snprintf(path, sizeof(path), "%s/destination", workspace);
            int failed = run_case(kp, opts, (enum operation)which, (enum fault)mode,
                path, which == SAVE_PRIVATE ? private_key : public_key,
                which == SAVE_PRIVATE ? private_size : public_size);
            fprintf(stderr, "%s: %s: %s\n", failed ? "FAIL" : "PASS", names[which], faults[mode]);
            failures += (unsigned)failed;
            ++cases;
        }
    }
    zuptsdk_keypair_destroy(kp);
    zuptsdk_options_destroy(opts);
    zuptsdk_secure_zero(private_key, sizeof(private_key));
    if (rmdir(workspace)) { perror("fixture cleanup"); ++failures; }
    fprintf(stderr, "Read-stop tests: %u cases, %u failures\n", cases, failures);
    return failures ? 1 : 0;
}
