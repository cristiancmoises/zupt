/* SPDX-License-Identifier: AGPL-3.0-or-later */
#define _DEFAULT_SOURCE 1
#include "zuptsdk.h"
#include "zupt.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int __real_open(const char *, int, ...);
int __wrap_open(const char *, int, ...);
int __real_fchmod(int, mode_t);
int __wrap_fchmod(int, mode_t);
ssize_t __real_write(int, const void *, size_t);
ssize_t __wrap_write(int, const void *, size_t);
int __real_fsync(int);
int __wrap_fsync(int);
int __real_close(int);
int __wrap_close(int);
int __real_unlink(const char *);
int __wrap_unlink(const char *);
void __real_zupt_random_bytes(uint8_t *, size_t);
void __wrap_zupt_random_bytes(uint8_t *, size_t);
int __real_zupt_mlkem768_keygen(uint8_t *, uint8_t *);
int __wrap_zupt_mlkem768_keygen(uint8_t *, uint8_t *);

/* Weak references let the baseline report the missing ownership contract as a
 * test failure while its existing public entry points run real regressions. */
int zupt_hybrid_keygen_created(const char *, int *) __attribute__((weak));
int zupt_hybrid_export_pubkey_created(const char *, const char *, int *) __attribute__((weak));

enum operation { SDK_PRIVATE, SDK_PAIR_PUBLIC, SDK_DERIVED_PUBLIC,
    CORE_PRIVATE, CORE_PUBLIC, CREATED_PRIVATE, CREATED_PUBLIC, OP_COUNT };
enum fault { PRECREATE, PERMISSIONS, WRITE_ERROR, WRITE_ZERO, WRITE_PARTIAL,
    SYNC_ERROR, CLOSE_ERROR, WRITE_AND_CLOSE, FAULT_COUNT };
static const char *const operation_names[] = {"SDK private", "SDK pair public",
    "SDK derived public", "legacy private", "legacy public",
    "created private", "created public"};
static const char *const fault_names[] = {"before creation", "permissions",
    "write error", "zero write", "partial write", "sync", "close", "write then close"};
static const char sentinel[] = "foreign key output remains caller-owned\n";
static char root[128], staging[160], fixture_path[192], target_path[256];
static zuptsdk_privkey_t *fixture_key;
static size_t live_allocs;
static int cases, failures, fault_seen, close_fault_seen, target_fd = -1, target_created;
static int injecting, clobber_cleanup, fail_crypto;
static unsigned write_calls;
static enum fault selected_fault;

int __wrap_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    int target = injecting && (flags & O_CREAT) && strcmp(path, target_path) == 0;
    if (target && selected_fault == PRECREATE) {
        ++fault_seen;
        errno = EACCES;
        return -1;
    }
    int fd = flags & O_CREAT ? __real_open(path, flags, mode) : __real_open(path, flags);
    if (target && fd >= 0) { target_fd = fd; target_created = 1; }
    return fd;
}

int __wrap_fchmod(int fd, mode_t mode) {
    if (injecting && fd == target_fd && selected_fault == PERMISSIONS) {
        ++fault_seen;
        errno = EPERM;
        return -1;
    }
    return __real_fchmod(fd, mode);
}

ssize_t __wrap_write(int fd, const void *bytes, size_t size) {
    if (injecting && fd == target_fd) {
        ++write_calls;
        if ((selected_fault == WRITE_PARTIAL || selected_fault == WRITE_AND_CLOSE) && write_calls == 1) {
            ++fault_seen;
            return __real_write(fd, bytes, size < 17 ? size : 17);
        }
        if (selected_fault == WRITE_ERROR || selected_fault == WRITE_PARTIAL || selected_fault == WRITE_AND_CLOSE) {
            ++fault_seen;
            errno = ENOSPC;
            return -1;
        }
        if (selected_fault == WRITE_ZERO) { ++fault_seen; return 0; }
    }
    return __real_write(fd, bytes, size);
}

int __wrap_fsync(int fd) {
    if (injecting && fd == target_fd && selected_fault == SYNC_ERROR) {
        ++fault_seen;
        errno = ENOSPC;
        return -1;
    }
    return __real_fsync(fd);
}

int __wrap_close(int fd) {
    int target = injecting && fd == target_fd;
    int rc = __real_close(fd);
    if (target) {
        target_fd = -1;
        if (selected_fault == CLOSE_ERROR || selected_fault == WRITE_AND_CLOSE) {
            ++fault_seen;
            ++close_fault_seen;
            errno = EIO;
            return -1;
        }
    }
    return rc;
}

int __wrap_unlink(const char *path) {
    int rc = __real_unlink(path);
    if (clobber_cleanup) errno = ECHILD;
    return rc;
}

void __wrap_zupt_random_bytes(uint8_t *bytes, size_t size) {
    if (size == 8) memset(bytes, 0x42, size);
    else __real_zupt_random_bytes(bytes, size);
}

int __wrap_zupt_mlkem768_keygen(uint8_t *public_key, uint8_t *private_key) {
    if (fail_crypto) { errno = ENODATA; return -1; }
    return __real_zupt_mlkem768_keygen(public_key, private_key);
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
    if (clobber_cleanup) errno = ECHILD;
}
static void *test_realloc(void *opaque, void *memory, size_t size) {
    if (!memory) return test_malloc(opaque, size);
    if (!size) { test_free(opaque, memory); return NULL; }
    return realloc(memory, size);
}

static void result(const char *name, int ok) {
    ++cases;
    failures += !ok;
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
}
static int descriptors(void) {
    int count = 0;
    for (int fd = 0; fd < 256; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static int entries(void) {
    DIR *directory = opendir(staging);
    if (!directory) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
    if (closedir(directory) != 0) return -1;
    return count;
}
static int is_private(enum operation operation) {
    return operation == SDK_PRIVATE || operation == CORE_PRIVATE || operation == CREATED_PRIVATE;
}
static int is_sdk(enum operation operation) { return operation <= SDK_DERIVED_PUBLIC; }
static void select_path(enum operation operation) {
    if (is_sdk(operation))
        snprintf(target_path, sizeof(target_path), "%s/zsdk_%s_%d_4242424242424242",
            staging, is_private(operation) ? "priv" : "pub", (int)getpid());
    else snprintf(target_path, sizeof(target_path), "%s/core.key", staging);
}
static int operation_available(enum operation operation) {
    return operation == CREATED_PRIVATE ? zupt_hybrid_keygen_created != NULL :
        operation == CREATED_PUBLIC ? zupt_hybrid_export_pubkey_created != NULL : 1;
}
static int invoke(enum operation operation, int *created, int *unchanged) {
    zuptsdk_keypair_t *pair = (zuptsdk_keypair_t *)(uintptr_t)1;
    zuptsdk_pubkey_t *pub = (zuptsdk_pubkey_t *)(uintptr_t)1;
    int rc;
    if (operation == SDK_PRIVATE || operation == SDK_PAIR_PUBLIC) {
        rc = zuptsdk_keypair_generate(NULL, &pair);
        *unchanged = pair == (zuptsdk_keypair_t *)(uintptr_t)1;
        if (!*unchanged) zuptsdk_keypair_destroy(pair);
    } else if (operation == SDK_DERIVED_PUBLIC) {
        rc = zuptsdk_privkey_get_public(fixture_key, &pub);
        *unchanged = pub == (zuptsdk_pubkey_t *)(uintptr_t)1;
        if (!*unchanged) zuptsdk_pubkey_destroy(pub);
    } else if (operation == CORE_PRIVATE) rc = zupt_hybrid_keygen(target_path);
    else if (operation == CORE_PUBLIC) rc = zupt_hybrid_export_pubkey(fixture_path, target_path);
    else if (operation == CREATED_PRIVATE) rc = zupt_hybrid_keygen_created(target_path, created);
    else rc = zupt_hybrid_export_pubkey_created(fixture_path, target_path, created);
    return rc;
}

static void fault_case(enum operation operation, enum fault fault) {
    char name[128];
    snprintf(name, sizeof(name), "%s %s preserves ownership and first error",
        operation_names[operation], fault_names[fault]);
    if (!operation_available(operation)) { result(name, 0); return; }
    select_path(operation);
    size_t allocations = live_allocs;
    int handles = descriptors(), created = 7, unchanged = 1;
    selected_fault = fault;
    fault_seen = close_fault_seen = target_created = 0;
    target_fd = -1;
    write_calls = 0;
    injecting = 1;
    clobber_cleanup = is_sdk(operation);
    int rc = invoke(operation, &created, &unchanged);
    int returned_errno = errno;
    clobber_cleanup = injecting = 0;
    int expected_errno = fault == PRECREATE ? EACCES : fault == PERMISSIONS ? EPERM :
        fault == WRITE_ZERO || fault == CLOSE_ERROR ? EIO : ENOSPC;
    struct stat metadata;
    int exists = lstat(target_path, &metadata) == 0;
    int owned = fault != PRECREATE;
    size_t expected_size = fault == WRITE_PARTIAL || fault == WRITE_AND_CLOSE ? 17 :
        fault == SYNC_ERROR || fault == CLOSE_ERROR ? (is_private(operation) ? 3664 : 1232) : 0;
    int retained = !is_sdk(operation) && owned;
    int expected_faults = fault == WRITE_AND_CLOSE ? 3 : fault == WRITE_PARTIAL ? 2 : 1;
    int ok = rc == (is_sdk(operation) ? ZUPTSDK_ERR_CRYPTO_FAIL : -1) &&
        unchanged && fault_seen == expected_faults && target_created == owned &&
        ((fault != WRITE_PARTIAL && fault != WRITE_AND_CLOSE) || write_calls == 2) &&
        close_fault_seen == (fault == CLOSE_ERROR || fault == WRITE_AND_CLOSE) &&
        exists == retained && entries() == retained &&
        (!retained || ((size_t)metadata.st_size == expected_size &&
            (!is_private(operation) || (metadata.st_mode & 0777) == 0600))) &&
        (operation < CREATED_PRIVATE || created == owned) &&
        live_allocs == allocations && descriptors() == handles &&
        (is_sdk(operation) ? strstr(zuptsdk_last_error_detail(), strerror(expected_errno)) != NULL :
                            returned_errno == expected_errno);
    if (!ok) fprintf(stderr, "  rc=%d detail=%s errno=%d fault=%d created=%d/%d exists=%d entries=%d alloc=%zu/%zu\n",
        rc, zuptsdk_last_error_detail(), returned_errno, fault_seen, created, target_created,
        exists, entries(), live_allocs, allocations);
    result(name, ok);
    if (exists) (void)unlink(target_path);
}

static int write_sentinel(const char *path) {
    FILE *stream = fopen(path, "wb");
    if (!stream) return 0;
    int ok = fwrite(sentinel, 1, sizeof(sentinel) - 1, stream) == sizeof(sentinel) - 1;
    if (fclose(stream) != 0) ok = 0;
    return ok;
}
static void writer_contract_case(enum fault fault) {
    select_path(CORE_PRIVATE);
    selected_fault = fault;
    fault_seen = close_fault_seen = target_created = 0;
    target_fd = -1;
    write_calls = 0;
    int handles = descriptors();
    injecting = 1;
    int rc = zupt_keyfile_write_new(target_path, (const uint8_t *)sentinel,
        sizeof(sentinel) - 1, 1);
    int returned_errno = errno;
    injecting = 0;
    struct stat metadata;
    int exists = lstat(target_path, &metadata) == 0;
    size_t expected_size = fault == WRITE_PARTIAL ? 17 : sizeof(sentinel) - 1;
    char bytes[sizeof(sentinel)] = {0};
    FILE *stream = fopen(target_path, "rb");
    size_t size = stream ? fread(bytes, 1, sizeof(bytes), stream) : 0;
    int closed = stream ? fclose(stream) : -1;
    result(fault == WRITE_PARTIAL ? "legacy shared writer retains partial output" :
        "legacy shared writer retains sync-uncertain output",
        rc == -1 && returned_errno == ENOSPC && target_created && exists &&
        fault_seen == (fault == WRITE_PARTIAL ? 2 : 1) &&
        (metadata.st_mode & 0777) == 0600 && (size_t)metadata.st_size == expected_size &&
        closed == 0 && size == expected_size && memcmp(bytes, sentinel, size) == 0 &&
        descriptors() == handles && entries() == 1);
    if (exists) (void)unlink(target_path);
}
static int same_sentinel(const char *path, const struct stat *before) {
    struct stat after;
    char bytes[sizeof(sentinel)];
    FILE *stream = fopen(path, "rb");
    if (!stream) return 0;
    size_t size = fread(bytes, 1, sizeof(bytes), stream);
    int closed = fclose(stream);
    return closed == 0 && lstat(path, &after) == 0 &&
        before->st_dev == after.st_dev && before->st_ino == after.st_ino &&
        size == sizeof(sentinel) - 1 && memcmp(bytes, sentinel, size) == 0;
}
static void collision_case(enum operation operation, int link_kind) {
    select_path(operation);
    char name[128], foreign[192];
    snprintf(name, sizeof(name), "%s collision preserves %s", operation_names[operation],
        link_kind == 1 ? "symlink" : link_kind == 2 ? "hardlink" : "regular file");
    if (!operation_available(operation)) { result(name, 0); return; }
    snprintf(foreign, sizeof(foreign), "%s/foreign", root);
    int setup = write_sentinel(link_kind ? foreign : target_path);
    if (setup && link_kind) setup = (link_kind == 1 ? symlink(foreign, target_path) : link(foreign, target_path)) == 0;
    struct stat before;
    setup = setup && lstat(target_path, &before) == 0;
    size_t allocations = live_allocs;
    int handles = descriptors(), created = 7, unchanged = 1;
    int rc = setup ? invoke(operation, &created, &unchanged) : 0;
    int ok = setup && rc == (is_sdk(operation) ? ZUPTSDK_ERR_CRYPTO_FAIL : -1) && unchanged &&
        same_sentinel(target_path, &before) && entries() == 1 &&
        (operation < CREATED_PRIVATE || created == 0) &&
        live_allocs == allocations && descriptors() == handles;
    result(name, ok);
    (void)unlink(target_path);
    if (link_kind) (void)unlink(foreign);
}

static void prewrite_cases(void) {
    select_path(CREATED_PRIVATE);
    int setup = write_sentinel(target_path);
    struct stat before;
    setup = setup && lstat(target_path, &before) == 0;
    int created = 7;
    fail_crypto = 1;
    int rc = zupt_hybrid_keygen_created ? zupt_hybrid_keygen_created(target_path, &created) : 0;
    fail_crypto = 0;
    result("crypto failure resets creation status and preserves foreign output",
        setup && rc == -1 && created == 0 && same_sentinel(target_path, &before));
    created = 7;
    rc = zupt_hybrid_export_pubkey_created ?
        zupt_hybrid_export_pubkey_created("/nonexistent/zupt-key-fixture", target_path, &created) : 0;
    result("private-key load failure resets creation status and preserves foreign output",
        setup && rc == -1 && created == 0 && same_sentinel(target_path, &before));
    created = 7;
    rc = zupt_hybrid_keygen_created ? zupt_hybrid_keygen_created(NULL, &created) : 0;
    result("writer validation failure resets creation status",
        rc == -1 && created == 0 && same_sentinel(target_path, &before));
    (void)unlink(target_path);
}

int main(void) {
    zuptsdk_allocator_t allocator = {test_malloc, test_free, test_realloc, NULL};
    if (zuptsdk_set_allocator(&allocator) != ZUPTSDK_OK) return 1;
    strcpy(root, "/tmp/zupt-sdk-key-write.XXXXXX");
    if (!mkdtemp(root)) return 1;
    snprintf(staging, sizeof(staging), "%s/staging", root);
    snprintf(fixture_path, sizeof(fixture_path), "%s/fixture.key", root);
    if (mkdir(staging, 0700) != 0 || setenv("TMPDIR", staging, 1) != 0) return 1;
    zuptsdk_keypair_t *pair = NULL;
    int setup = zuptsdk_keypair_generate(NULL, &pair) == ZUPTSDK_OK &&
        zuptsdk_keypair_save_private(pair, fixture_path) == ZUPTSDK_OK;
    zuptsdk_keypair_destroy(pair);
    setup = setup && zuptsdk_privkey_load(fixture_path, &fixture_key) == ZUPTSDK_OK && entries() == 0;
    result("real generated private-key fixture is usable", setup);
    if (!setup) return 1;
    for (enum operation operation = 0; operation < OP_COUNT; ++operation)
        for (enum fault fault = 0; fault < FAULT_COUNT; ++fault)
            if (fault != PERMISSIONS || is_private(operation)) fault_case(operation, fault);
    const enum operation collision_operations[] = {
        SDK_PRIVATE, SDK_PAIR_PUBLIC, SDK_DERIVED_PUBLIC, CREATED_PRIVATE, CREATED_PUBLIC};
    for (size_t i = 0; i < sizeof(collision_operations) / sizeof(collision_operations[0]); ++i)
        for (int kind = 0; kind < 3; ++kind) collision_case(collision_operations[i], kind);
    writer_contract_case(WRITE_PARTIAL);
    writer_contract_case(SYNC_ERROR);
    prewrite_cases();
    zuptsdk_privkey_destroy(fixture_key);
    (void)unlink(fixture_path);
    result("all fixture allocations and owned temporary outputs released", live_allocs == 0 && entries() == 0);
    (void)rmdir(staging);
    (void)rmdir(root);
    printf("Key-write failures: %d cases, %d failures\n", cases, failures);
    return failures != 0;
}
