/* SPDX-License-Identifier: AGPL-3.0-or-later */
#define _DEFAULT_SOURCE 1
#include "zuptsdk.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void __real_zupt_random_bytes(uint8_t *, size_t);
void __wrap_zupt_random_bytes(uint8_t *, size_t);
FILE *__real_fopen(const char *, const char *);
FILE *__wrap_fopen(const char *, const char *);
FILE *__real_fdopen(int, const char *);
FILE *__wrap_fdopen(int, const char *);
int __real_fclose(FILE *);
int __wrap_fclose(FILE *);
int __real_fchmod(int, mode_t);
int __wrap_fchmod(int, mode_t);
size_t __real_fwrite(const void *, size_t, size_t, FILE *);
size_t __wrap_fwrite(const void *, size_t, size_t, FILE *);

enum operation { COMPRESS_STREAM, COMPRESS_BUFFER, EXTRACT_DIR, VERIFY,
                 DECOMPRESS_STREAM, OP_COUNT };
enum failure { NO_FAILURE, FDOPEN_FAILURE, WRITE_FAILURE, CLOSE_FAILURE,
               PERMISSION_FAILURE };
static const uint8_t payload[] = "private staging regression\n";
static const char sentinel[] = "existing file must survive\n";
static char stage_path[1024];
static FILE *stage_stream;
static enum failure failure;
static unsigned observed, injected, private_mode, close_on_exec;
static uint8_t *fixture;
static size_t fixture_size;

void __wrap_zupt_random_bytes(uint8_t *data, size_t size) {
    if (size == 8) memset(data, 0x42, size);
    else __real_zupt_random_bytes(data, size);
}

static void observe(FILE *stream) {
    struct stat st;
    ++observed;
    if (fstat(fileno(stream), &st) == 0)
        private_mode &= (st.st_mode & 0777) == 0600;
    else private_mode = 0;
    int flags = fcntl(fileno(stream), F_GETFD);
    close_on_exec &= flags >= 0 && (flags & FD_CLOEXEC) != 0;
    stage_stream = stream;
}

FILE *__wrap_fopen(const char *path, const char *mode) {
    FILE *stream = __real_fopen(path, mode);
    if (stream && strcmp(path, stage_path) == 0 && strcmp(mode, "wb") == 0)
        observe(stream);
    return stream;
}

FILE *__wrap_fdopen(int descriptor, const char *mode) {
    struct stat actual, named;
    int matches = strcmp(mode, "wb") == 0 && fstat(descriptor, &actual) == 0 &&
        lstat(stage_path, &named) == 0 && actual.st_dev == named.st_dev &&
        actual.st_ino == named.st_ino;
    if (matches && failure == FDOPEN_FAILURE) {
        ++injected;
        errno = EMFILE;
        return NULL;
    }
    FILE *stream = __real_fdopen(descriptor, mode);
    if (matches && stream) observe(stream);
    return stream;
}

int __wrap_fchmod(int descriptor, mode_t mode) {
    struct stat actual, named;
    if (failure == PERMISSION_FAILURE && fstat(descriptor, &actual) == 0 &&
        lstat(stage_path, &named) == 0 && actual.st_dev == named.st_dev &&
        actual.st_ino == named.st_ino) {
        ++injected;
        errno = EACCES;
        return -1;
    }
    return __real_fchmod(descriptor, mode);
}

size_t __wrap_fwrite(const void *data, size_t size, size_t count, FILE *stream) {
    if (stream == stage_stream && failure == WRITE_FAILURE) {
        ++injected;
        errno = ENOSPC;
        return 0;
    }
    return __real_fwrite(data, size, count, stream);
}

int __wrap_fclose(FILE *stream) {
    int target = stream == stage_stream;
    if (target) stage_stream = NULL;
    int status = __real_fclose(stream);
    if (target && failure == CLOSE_FAILURE) {
        ++injected;
        errno = EIO;
        return EOF;
    }
    return status;
}

struct input { const uint8_t *bytes; size_t size, offset; };
static int64_t read_input(void *opaque, uint8_t *buffer, size_t capacity) {
    struct input *input = opaque;
    size_t size = input->size - input->offset;
    if (size > capacity) size = capacity;
    if (size) memcpy(buffer, input->bytes + input->offset, size);
    input->offset += size;
    return (int64_t)size;
}

static int64_t discard(void *opaque, const uint8_t *buffer, size_t size) {
    (void)opaque; (void)buffer;
    return (int64_t)size;
}

static int open_descriptors(void) {
    int count = 0;
    for (int fd = 0; fd < 256; ++fd)
        if (fcntl(fd, F_GETFD) != -1) ++count;
    return count;
}

static int invoke(enum operation operation, const char *destination) {
    struct input input = {payload, sizeof(payload) - 1, 0};
    uint8_t *archive = NULL;
    size_t archive_size = 0;
    int status;
    switch (operation) {
    case COMPRESS_STREAM:
        return zuptsdk_compress_stream(NULL, NULL, read_input, &input,
            "input.txt", input.size, discard, NULL, NULL, NULL);
    case COMPRESS_BUFFER:
        status = zuptsdk_compress_buffer(NULL, NULL, "input.txt", payload,
            sizeof(payload) - 1, NULL, NULL, &archive, &archive_size);
        zuptsdk_free(archive);
        return status;
    case EXTRACT_DIR:
        return zuptsdk_extract_to_dir(NULL, fixture, fixture_size, destination,
                                      NULL, NULL);
    case VERIFY:
        return zuptsdk_verify(NULL, fixture, fixture_size, NULL, NULL);
    case DECOMPRESS_STREAM:
        input.bytes = fixture; input.size = fixture_size;
        return zuptsdk_decompress_stream(NULL, read_input, &input, discard,
                                         NULL, NULL, NULL);
    case OP_COUNT: break;
    }
    return ZUPTSDK_ERR_INVALID_ARG;
}

static int matches_sentinel(const char *path) {
    char bytes[sizeof(sentinel)] = {0};
    FILE *stream = __real_fopen(path, "rb");
    if (!stream) return 0;
    size_t count = fread(bytes, 1, sizeof(bytes), stream);
    int status = __real_fclose(stream);
    return status == 0 && count == sizeof(sentinel) - 1 &&
        memcmp(bytes, sentinel, sizeof(sentinel) - 1) == 0;
}

static int run_case(enum operation operation, int collision,
                     enum failure requested_failure) {
    char directory[] = "/tmp/zupt-sdk-staging.XXXXXX";
    char target[1024], destination[1024], extracted[1100];
    if (!mkdtemp(directory) || setenv("TMPDIR", directory, 1) != 0) return 1;
    const char *prefix = operation <= COMPRESS_BUFFER ? "zsdk_in" :
        operation == VERIFY ? "zsdk_v" : "zsdk_arc";
    snprintf(stage_path, sizeof(stage_path), "%s/%s_%ld_4242424242424242",
             directory, prefix, (long)getpid());
    snprintf(target, sizeof(target), "%s/sentinel", directory);
    snprintf(destination, sizeof(destination), "%s/extracted", directory);
    snprintf(extracted, sizeof(extracted), "%s/input.txt", destination);
    FILE *stream = __real_fopen(target, "wb");
    if (!stream) return 1;
    size_t written = __real_fwrite(sentinel, 1, sizeof(sentinel) - 1, stream);
    if (__real_fclose(stream) != 0 || written != sizeof(sentinel) - 1) return 1;
    if (collision == 1 && link(target, stage_path) != 0) return 1;
    if (collision == 2 && symlink(target, stage_path) != 0) return 1;
    if (collision == 3) {
        stream = __real_fopen(stage_path, "wb");
        if (!stream) return 1;
        written = __real_fwrite(sentinel, 1, sizeof(sentinel) - 1, stream);
        if (__real_fclose(stream) != 0 || written != sizeof(sentinel) - 1) return 1;
    }
    struct stat collision_before, target_before;
    if (collision && (lstat(stage_path, &collision_before) != 0 ||
                      lstat(target, &target_before) != 0)) return 1;
    observed = injected = 0;
    private_mode = close_on_exec = 1;
    stage_stream = NULL;
    failure = requested_failure;
    int before = open_descriptors();
    mode_t saved_umask = umask(0);
    int status = invoke(operation, destination);
    umask(saved_umask);
    struct stat info;
    int exists = lstat(stage_path, &info) == 0;
    int expected = collision || failure ? ZUPTSDK_ERR_IO : ZUPTSDK_OK;
    int failed = status != expected || open_descriptors() != before;
    if (collision) {
        struct stat target_after;
        failed |= observed != 0 || !exists || !matches_sentinel(target) ||
            !matches_sentinel(stage_path);
        if (exists) failed |= info.st_dev != collision_before.st_dev ||
                              info.st_ino != collision_before.st_ino;
        if (lstat(target, &target_after) != 0) failed = 1;
        else failed |= target_after.st_dev != target_before.st_dev ||
                       target_after.st_ino != target_before.st_ino;
        if (collision == 1 && exists)
            failed |= info.st_dev != target_before.st_dev ||
                      info.st_ino != target_before.st_ino;
        if (collision == 2 && exists) failed |= !S_ISLNK(info.st_mode);
    } else {
        failed |= exists || stage_stream != NULL;
        if (failure == FDOPEN_FAILURE || failure == PERMISSION_FAILURE)
            failed |= injected != 1;
        else failed |= !observed || !private_mode || !close_on_exec;
        if (failure == WRITE_FAILURE || failure == CLOSE_FAILURE)
            failed |= injected == 0;
    }
    fprintf(stderr, "%s: op=%d collision=%d fault=%d status=%d "
        "observed=%u private=%u cloexec=%u injected=%u exists=%d\n",
        failed ? "FAIL" : "PASS", operation, collision, failure, status,
        observed, private_mode, close_on_exec, injected, exists);
    unlink(stage_path); unlink(target); unlink(extracted); rmdir(destination);
    rmdir(directory);
    stage_path[0] = '\0';
    return failed;
}

int main(void) {
    /* Generate one valid archive through the unchanged public buffer API. */
    char directory[] = "/tmp/zupt-sdk-staging-fixture.XXXXXX";
    if (!mkdtemp(directory) || setenv("TMPDIR", directory, 1) != 0) return 2;
    int status = zuptsdk_compress_buffer(NULL, NULL, "input.txt", payload,
        sizeof(payload) - 1, NULL, NULL, &fixture, &fixture_size);
    rmdir(directory);
    if (status != ZUPTSDK_OK) return 2;
    unsigned failed = 0, cases = 0;
    for (int op = 0; op < OP_COUNT; ++op) {
        for (int collision = 0; collision <= 3; ++collision) {
            failed += (unsigned)run_case((enum operation)op, collision, NO_FAILURE);
            ++cases;
        }
        for (int fault = FDOPEN_FAILURE; fault <= PERMISSION_FAILURE; ++fault) {
            failed += (unsigned)run_case((enum operation)op, 0, (enum failure)fault);
            ++cases;
        }
    }
    zuptsdk_free(fixture);
    fprintf(stderr, "SDK staging: %u cases, %u failures\n", cases, failed);
    return failed ? 1 : 0;
}
