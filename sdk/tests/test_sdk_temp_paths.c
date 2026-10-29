/* SPDX-License-Identifier: AGPL-3.0-or-later */
#define _DEFAULT_SOURCE 1
#include "zuptsdk.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __GLIBC__
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
int __wrap_snprintf(char *, size_t, const char *, ...);
#ifdef __GLIBC__
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 5, 6)))
#endif
int __wrap___snprintf_chk(char *, size_t, int, size_t, const char *, ...);
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 5, 0)))
#endif
int __wrap___vsnprintf_chk(char *, size_t, int, size_t, const char *, va_list);
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 5, 0)))
#endif
int __real___vsnprintf_chk(char *, size_t, int, size_t, const char *, va_list);
#endif
void __real_zupt_random_bytes(uint8_t *, size_t);
void __wrap_zupt_random_bytes(uint8_t *, size_t);

enum operation { KEYPAIR, PUBLIC_KEY, COMPRESS_FILES, COMPRESS_BUFFER,
    EXTRACT_DIR, EXTRACT_BUFFER, COMPRESS_STREAM, DECOMPRESS_STREAM, VERIFY,
    OP_COUNT };
static const char *const names[] = {"keypair", "public key", "compress files",
    "compress buffer", "extract directory", "extract buffer", "compress stream",
    "decompress stream", "verify"};
static const unsigned path_counts[] = {2, 1, 1, 2, 1, 2, 2, 3, 1};
static const char foreign_bytes[] = "foreign temporary-path collision\n";
static const uint8_t payload[] = "temporary path regression\n";
static char root[128], staging[768], input_path[160], key_path[160];
static char destination[160], destination_file[192], foreign_path[1024];
static uint8_t *fixture;
static size_t fixture_size, live_allocs;
static zuptsdk_privkey_t *private_key;
static zuptsdk_secure_buf_t *password;
static unsigned format_fail_at, format_calls, input_calls, output_calls;
static int cases, failures;

/* snprintf errors may leave output bytes. Make those bytes name a real foreign
 * file, so merely checking a plausible output string cannot pass these tests. */
static int inject_format_error(char *out, size_t cap, const char *format) {
    if (cap == 512 && strcmp(format, "%s/%s_%d_%02x%02x%02x%02x%02x%02x%02x%02x") == 0 &&
        ++format_calls == format_fail_at) {
        size_t n = strlen(foreign_path);
        if (n >= cap) n = cap - 1;
        memcpy(out, foreign_path, n);
        out[n] = 0;
        errno = EILSEQ;
        return 1;
    }
    return 0;
}

int __wrap_snprintf(char *out, size_t cap, const char *format, ...) {
    if (inject_format_error(out, cap, format)) return -1;
    va_list args;
    va_start(args, format);
#ifdef __GLIBC__
    /* The plain entry point carries no object size. Preserve the active glibc
     * format checks without passing through the wrapped checked entry again. */
    int n = __real___vsnprintf_chk(out, cap,
        __USE_FORTIFY_LEVEL > 1 ? __USE_FORTIFY_LEVEL - 1 : 0,
        (size_t)-1, format, args);
#else
    int n = vsnprintf(out, cap, format, args);
#endif
    va_end(args);
    return n;
}

#ifdef __GLIBC__
/* Fortified glibc builds call these entry points instead of snprintf. Keep the
 * bounds and format checks when no formatting failure is being injected. */
int __wrap___vsnprintf_chk(char *out, size_t cap, int flag, size_t object_size,
                           const char *format, va_list args) {
    if (inject_format_error(out, cap, format)) return -1;
    return __real___vsnprintf_chk(out, cap, flag, object_size, format, args);
}

int __wrap___snprintf_chk(char *out, size_t cap, int flag, size_t object_size,
                          const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = __wrap___vsnprintf_chk(out, cap, flag, object_size, format, args);
    va_end(args);
    return n;
}
#endif

void __wrap_zupt_random_bytes(uint8_t *data, size_t size) {
    if (size == 8) memset(data, 0x42, size);
    else __real_zupt_random_bytes(data, size);
}

static void *test_malloc(void *opaque, size_t size) {
    (void)opaque;
    void *memory = malloc(size);
    if (memory) ++live_allocs;
    return memory;
}
static void test_free(void *opaque, void *memory) {
    (void)opaque;
    if (memory) { --live_allocs; free(memory); }
}
static void *test_realloc(void *opaque, void *memory, size_t size) {
    if (!memory) return test_malloc(opaque, size);
    if (!size) { test_free(opaque, memory); return NULL; }
    return realloc(memory, size);
}

static void result(const char *name, int ok) {
    ++cases;
    if (!ok) ++failures;
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
}
#ifdef __GLIBC__
static void checked_format_controls(void) {
    char out[32];
    int n = __wrap___snprintf_chk(out, sizeof(out), 2, sizeof(out), "%s", "checked");
    result("checked formatter preserves valid output", n == 7 && strcmp(out, "checked") == 0);

    int descriptors[2];
    if (pipe(descriptors) != 0) {
        result("checked formatter enforces reported object bound", 0);
        return;
    }
    pid_t child = fork();
    if (child == 0) {
        struct rlimit no_core = {0, 0};
        (void)close(descriptors[0]);
        if (dup2(descriptors[1], STDERR_FILENO) < 0 ||
            setrlimit(RLIMIT_CORE, &no_core) != 0) _exit(90);
        (void)close(descriptors[1]);
        (void)alarm(5);
        /* The backing buffer fits the text even if the reported bound is lost.
         * Only real glibc object-bound enforcement should abort this call. */
        (void)__wrap___snprintf_chk(out, sizeof(out), 2, 1, "%s", "abc");
        _exit(91);
    }
    (void)close(descriptors[1]);
    char diagnostic[512];
    size_t used = 0;
    int read_ok = 1;
    while (child > 0 && used < sizeof(diagnostic) - 1) {
        ssize_t count = read(descriptors[0], diagnostic + used, sizeof(diagnostic) - 1 - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) read_ok = 0;
        if (count <= 0) break;
        used += (size_t)count;
    }
    diagnostic[used] = 0;
    if (close(descriptors[0]) != 0) read_ok = 0;
    int status = 0;
    pid_t waited;
    do { waited = child > 0 ? waitpid(child, &status, 0) : -1; }
    while (child > 0 && waited < 0 && errno == EINTR);
    fprintf(stderr, "FORTIFY NEGATIVE CONTROL: expected glibc SIGABRT; child stderr follows\n");
    (void)fwrite(diagnostic, 1, used, stderr);
    if (!used || diagnostic[used - 1] != '\n') (void)fputc('\n', stderr);
    result("checked formatter enforces reported object bound",
        child > 0 && waited == child && read_ok && used > 0 && used < sizeof(diagnostic) - 1 &&
        WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT &&
        strstr(diagnostic, "buffer overflow detected") != NULL &&
        strstr(diagnostic, "Sanitizer") == NULL &&
        strstr(diagnostic, "runtime error:") == NULL &&
        strstr(diagnostic, "DEADLYSIGNAL") == NULL);
}
#endif
static int descriptors(void) {
    int count = 0;
    for (int fd = 0; fd < 256; ++fd)
        if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static int entries(const char *path) {
    DIR *directory = opendir(path);
    if (!directory) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
    if (closedir(directory) != 0) return -1;
    return count;
}
static int write_bytes(const char *path, const void *bytes, size_t size) {
    FILE *stream = fopen(path, "wb");
    if (!stream) return 0;
    int ok = fwrite(bytes, 1, size, stream) == size;
    if (fclose(stream) != 0) ok = 0;
    return ok;
}
static int same_file(const char *path, const struct stat *before) {
    struct stat after;
    char bytes[sizeof(foreign_bytes)];
    FILE *stream = fopen(path, "rb");
    if (!stream) return 0;
    size_t n = fread(bytes, 1, sizeof(bytes), stream);
    int closed = fclose(stream);
    return closed == 0 && lstat(path, &after) == 0 &&
        after.st_dev == before->st_dev && after.st_ino == before->st_ino &&
        n == sizeof(foreign_bytes) - 1 &&
        memcmp(bytes, foreign_bytes, sizeof(foreign_bytes) - 1) == 0;
}
struct input { const uint8_t *bytes; size_t size, offset; };
static int64_t read_input(void *opaque, uint8_t *buffer, size_t capacity) {
    struct input *input = opaque;
    ++input_calls;
    size_t n = input->size - input->offset;
    if (n > capacity) n = capacity;
    memcpy(buffer, input->bytes + input->offset, n);
    input->offset += n;
    return (int64_t)n;
}
static int64_t discard(void *opaque, const uint8_t *bytes, size_t size) {
    (void)opaque; (void)bytes;
    ++output_calls;
    return (int64_t)size;
}

static void run_case(enum operation operation, unsigned nth, int long_path) {
    int setup = write_bytes(foreign_path, foreign_bytes, sizeof(foreign_bytes) - 1);
    struct stat before, destination_before;
    setup = setup && lstat(foreign_path, &before) == 0 &&
        lstat(destination_file, &destination_before) == 0;
    uint8_t sentinel = 0x7b, *out = &sentinel;
    size_t out_size = 987;
    zuptsdk_keypair_t *pair = (zuptsdk_keypair_t *)(uintptr_t)1;
    zuptsdk_pubkey_t *pub = (zuptsdk_pubkey_t *)(uintptr_t)1;
    struct input input = {operation == COMPRESS_STREAM ? payload : fixture,
        operation == COMPRESS_STREAM ? sizeof(payload) - 1 : fixture_size, 0};
    size_t allocations = live_allocs;
    int handles = descriptors(), files = entries(staging);
    format_calls = input_calls = output_calls = 0;
    format_fail_at = long_path ? 0 : nth;
    int status = ZUPTSDK_ERR_INTERNAL;
    switch (operation) {
    case KEYPAIR: status = zuptsdk_keypair_generate(NULL, &pair); break;
    case PUBLIC_KEY: status = zuptsdk_privkey_get_public(private_key, &pub); break;
    case COMPRESS_FILES: {
        const char *paths[] = {input_path};
        status = zuptsdk_compress_files(NULL, NULL, paths, 1, password, NULL, &out, &out_size);
        break;
    }
    case COMPRESS_BUFFER:
        status = zuptsdk_compress_buffer(NULL, NULL, "input.txt", payload,
            sizeof(payload) - 1, password, NULL, &out, &out_size); break;
    case EXTRACT_DIR:
        status = zuptsdk_extract_to_dir(NULL, fixture, fixture_size, destination, password, NULL); break;
    case EXTRACT_BUFFER:
        status = zuptsdk_extract_buffer(NULL, fixture, fixture_size, password, NULL, &out, &out_size); break;
    case COMPRESS_STREAM:
        status = zuptsdk_compress_stream(NULL, NULL, read_input, &input, "input.txt",
            input.size, discard, NULL, password, NULL); break;
    case DECOMPRESS_STREAM:
        status = zuptsdk_decompress_stream(NULL, read_input, &input, discard, NULL, password, NULL); break;
    case VERIFY: status = zuptsdk_verify(NULL, fixture, fixture_size, password, NULL); break;
    case OP_COUNT: break;
    }
    format_fail_at = 0;
    int unchanged = out == &sentinel && out_size == 987 && sentinel == 0x7b &&
        pair == (zuptsdk_keypair_t *)(uintptr_t)1 && pub == (zuptsdk_pubkey_t *)(uintptr_t)1;
    if (pair != (zuptsdk_keypair_t *)(uintptr_t)1) zuptsdk_keypair_destroy(pair);
    if (pub != (zuptsdk_pubkey_t *)(uintptr_t)1) zuptsdk_pubkey_destroy(pub);
    if (out != &sentinel) zuptsdk_free(out);
    uint8_t *pw_bytes = NULL;
    size_t pw_size = 0;
    int pw_ok = zuptsdk_secure_buf_get(password, &pw_bytes, &pw_size) == ZUPTSDK_OK &&
        pw_size == 6 && memcmp(pw_bytes, "secret", 6) == 0;
    int no_early_callback = (nth > 1 && operation != COMPRESS_STREAM) || input_calls == 0;
    char name[128];
    snprintf(name, sizeof(name), "%s %s path %u preserves outputs and foreign file",
        names[operation], long_path ? "truncated" : "format-error", nth);
    int ok = setup && status == ZUPTSDK_ERR_IO && unchanged && pw_ok &&
        strstr(zuptsdk_last_error_detail(), "temporary path") != NULL &&
        same_file(foreign_path, &before) && entries(staging) == files &&
        same_file(destination_file, &destination_before) && entries(destination) == 1 &&
        format_calls == (long_path ? 1 : nth) &&
        live_allocs == allocations && descriptors() == handles &&
        output_calls == 0 && no_early_callback;
    if (!ok) fprintf(stderr, "  status=%d detail=%s formats=%u input=%u output=%u files=%d/%d alloc=%zu/%zu\n",
        status, zuptsdk_last_error_detail(), format_calls, input_calls, output_calls,
        entries(staging), files, live_allocs, allocations);
    result(name, ok);
    (void)unlink(foreign_path);
}

int main(void) {
#ifdef __GLIBC__
    checked_format_controls();
#endif
    zuptsdk_allocator_t allocator = {test_malloc, test_free, test_realloc, NULL};
    if (zuptsdk_set_allocator(&allocator) != ZUPTSDK_OK) return 1;
    strcpy(root, "/tmp/zupt-sdk-temp-paths.XXXXXX");
    if (!mkdtemp(root)) return 1;
    snprintf(staging, sizeof(staging), "%s/staging", root);
    snprintf(input_path, sizeof(input_path), "%s/input.txt", root);
    snprintf(key_path, sizeof(key_path), "%s/fixture.key", root);
    snprintf(destination, sizeof(destination), "%s/extracted", root);
    snprintf(destination_file, sizeof(destination_file), "%s/foreign", destination);
    snprintf(foreign_path, sizeof(foreign_path), "%s/foreign", staging);
    if (mkdir(staging, 0700) != 0 || setenv("TMPDIR", staging, 1) != 0 ||
        !write_bytes(input_path, payload, sizeof(payload) - 1) ||
        mkdir(destination, 0700) != 0 ||
        !write_bytes(destination_file, foreign_bytes, sizeof(foreign_bytes) - 1)) return 1;
    zuptsdk_keypair_t *pair = NULL;
    if (zuptsdk_keypair_generate(NULL, &pair) != ZUPTSDK_OK ||
        zuptsdk_keypair_save_private(pair, key_path) != ZUPTSDK_OK) return 1;
    zuptsdk_keypair_destroy(pair);
    if (zuptsdk_privkey_load(key_path, &private_key) != ZUPTSDK_OK ||
        zuptsdk_secure_buf_from_data((const uint8_t *)"secret", 6, &password) != ZUPTSDK_OK ||
        zuptsdk_compress_buffer(NULL, NULL, "input.txt", payload, sizeof(payload) - 1,
            NULL, NULL, &fixture, &fixture_size) != ZUPTSDK_OK) return 1;
    result("real fixtures are usable before fault injection",
        fixture_size > 0 && entries(staging) == 0 &&
        zuptsdk_verify(NULL, fixture, fixture_size, NULL, NULL) == ZUPTSDK_OK);

    for (enum operation operation = 0; operation < OP_COUNT; ++operation)
        for (unsigned nth = 1; nth <= path_counts[operation]; ++nth)
            run_case(operation, nth, 0);

    /* A real, accessible hierarchy longer than the helper's output buffer.
     * Its 511-byte prefix is a valid foreign file, not a nonexistent path. */
    char long_dir[768];
    snprintf(long_dir, sizeof(long_dir), "%s/long", root);
    if (mkdir(long_dir, 0700) != 0) return 1;
    while (strlen(long_dir) < 490) {
        size_t n = strlen(long_dir);
        size_t component = 490 - n - 1;
        if (component > 80) component = 80;
        long_dir[n++] = '/';
        memset(long_dir + n, 'a', component);
        long_dir[n + component] = 0;
        if (mkdir(long_dir, 0700) != 0) return 1;
    }
    strcpy(staging, long_dir);
    if (setenv("TMPDIR", staging, 1) != 0) return 1;
    for (enum operation operation = 0; operation < OP_COUNT; ++operation) {
        const char *prefix = operation == KEYPAIR ? "zsdk_priv" :
            operation == PUBLIC_KEY ? "zsdk_pub" : operation == EXTRACT_BUFFER ? "zsdk_x" :
            operation == COMPRESS_BUFFER || operation == COMPRESS_STREAM ? "zsdk_in" :
            operation == VERIFY ? "zsdk_v" : "zsdk_arc";
        int n = snprintf(foreign_path, sizeof(foreign_path), "%s/%s_%d_4242424242424242",
            staging, prefix, (int)getpid());
        if (n < 512) return 1;
        foreign_path[511] = 0;
        run_case(operation, 1, 1);
    }
    zuptsdk_free(fixture);
    zuptsdk_privkey_destroy(private_key);
    zuptsdk_secure_buf_destroy(password);
    result("all fixture allocations released", live_allocs == 0);
    (void)unlink(input_path);
    (void)unlink(key_path);
    (void)unlink(destination_file);
    (void)rmdir(destination);
    while (strlen(long_dir) > strlen(root)) {
        (void)rmdir(long_dir);
        char *slash = strrchr(long_dir, '/');
        if (!slash) break;
        *slash = 0;
    }
    snprintf(staging, sizeof(staging), "%s/staging", root);
    (void)rmdir(staging);
    (void)rmdir(root);
    printf("temporary paths: %d cases, %d failures\n", cases, failures);
    return failures != 0;
}
