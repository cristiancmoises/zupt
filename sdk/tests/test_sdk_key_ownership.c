/* SPDX-License-Identifier: AGPL-3.0-or-later */
#define _DEFAULT_SOURCE 1
#include "zuptsdk.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void __real_zupt_random_bytes(uint8_t *, size_t);
void __wrap_zupt_random_bytes(uint8_t *, size_t);

static size_t alloc_calls, fail_at, live_allocs;
static int failures, cases;
static const char sentinel[] = "keep existing key path\n";
static char root[128], staging[160], private_path[192], public_path[192];

/* Fix only temporary path nonces; key generation still uses the real CSPRNG. */
void __wrap_zupt_random_bytes(uint8_t *data, size_t size) {
    if (size == 8) memset(data, 0x42, size);
    else __real_zupt_random_bytes(data, size);
}

static void *test_malloc(void *opaque, size_t size) {
    (void)opaque;
    if (++alloc_calls == fail_at) return NULL;
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
    if (++alloc_calls == fail_at) return NULL;
    return realloc(memory, size);
}

static int descriptors(void) {
    int count = 0;
    for (int fd = 0; fd < 256; ++fd)
        if (fcntl(fd, F_GETFD) != -1) ++count;
    return count;
}

static int file_count(void) {
    DIR *directory = opendir(staging);
    if (!directory) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
    if (closedir(directory) != 0) return -1;
    return count;
}

static void clear_staging(void) {
    DIR *directory = opendir(staging);
    if (!directory) return;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", staging, entry->d_name);
        (void)unlink(path);
    }
    (void)closedir(directory);
}

static void result(const char *name, int ok) {
    ++cases;
    if (!ok) ++failures;
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
}

static void allocation_failure(size_t index, int derive) {
    zuptsdk_privkey_t *private_key = NULL;
    if (derive && zuptsdk_privkey_load(private_path, &private_key) != ZUPTSDK_OK) {
        result("load real private fixture", 0);
        return;
    }
    size_t before = live_allocs;
    int handles = descriptors();
    alloc_calls = 0;
    fail_at = index;
    int status;
    int unchanged;
    if (derive) {
        zuptsdk_pubkey_t *key = (zuptsdk_pubkey_t *)(uintptr_t)1;
        status = zuptsdk_privkey_get_public(private_key, &key);
        unchanged = key == (zuptsdk_pubkey_t *)(uintptr_t)1;
        if (status == ZUPTSDK_OK) zuptsdk_pubkey_destroy(key);
    } else {
        zuptsdk_keypair_t *pair = (zuptsdk_keypair_t *)(uintptr_t)1;
        status = zuptsdk_keypair_generate(NULL, &pair);
        unchanged = pair == (zuptsdk_keypair_t *)(uintptr_t)1;
        if (status == ZUPTSDK_OK) zuptsdk_keypair_destroy(pair);
    }
    fail_at = 0;
    char name[96];
    snprintf(name, sizeof(name), "%s allocation failure %zu removes owned files",
             derive ? "derived public key" : "keypair", index);
    result(name, status == ZUPTSDK_ERR_NO_MEMORY && unchanged &&
                 file_count() == 0 && live_allocs == before &&
                 descriptors() == handles);
    zuptsdk_privkey_destroy(private_key);
    clear_staging();
}

static int same_file(const char *path, const struct stat *before) {
    struct stat after;
    char data[sizeof(sentinel)];
    FILE *stream = fopen(path, "rb");
    if (!stream) return 0;
    size_t size = fread(data, 1, sizeof(data), stream);
    int closed = fclose(stream);
    return closed == 0 && lstat(path, &after) == 0 &&
           before->st_dev == after.st_dev && before->st_ino == after.st_ino &&
           size == sizeof(sentinel) - 1 &&
           memcmp(data, sentinel, sizeof(sentinel) - 1) == 0;
}

static size_t read_fixture(const char *path, uint8_t *bytes, size_t capacity) {
    FILE *stream = fopen(path, "rb");
    if (!stream) return 0;
    size_t size = fread(bytes, 1, capacity, stream);
    int valid = !ferror(stream) && feof(stream);
    if (fclose(stream) != 0) valid = 0;
    return valid ? size : 0;
}

static int fixture_matches(const char *path, const uint8_t *bytes, size_t size) {
    uint8_t observed[4096];
    size_t got = read_fixture(path, observed, sizeof(observed));
    return got == size && got != 0 && memcmp(observed, bytes, size) == 0;
}

static void collision(int public_collision, int link_kind, int derive) {
    char collision_path[256], target[192];
    snprintf(collision_path, sizeof(collision_path),
             "%s/zsdk_%s_%d_4242424242424242", staging,
             public_collision ? "pub" : "priv", (int)getpid());
    snprintf(target, sizeof(target), "%s/collision-target", root);
    const char *write_path = link_kind ? target : collision_path;
    FILE *stream = fopen(write_path, "wb");
    int setup = stream != NULL;
    if (stream) {
        setup = fwrite(sentinel, 1, sizeof(sentinel) - 1, stream) ==
                sizeof(sentinel) - 1;
        if (fclose(stream) != 0) setup = 0;
    }
    if (setup && link_kind)
        setup = (link_kind == 1 ? symlink(target, collision_path) :
                                 link(target, collision_path)) == 0;
    struct stat before;
    setup = setup && lstat(collision_path, &before) == 0;
    zuptsdk_privkey_t *private_key = NULL;
    if (derive)
        setup = setup && zuptsdk_privkey_load(private_path, &private_key) == ZUPTSDK_OK;
    size_t allocations = live_allocs;
    int handles = descriptors();
    int status = ZUPTSDK_OK, unchanged = 0;
    if (setup && derive) {
        zuptsdk_pubkey_t *key = (zuptsdk_pubkey_t *)(uintptr_t)1;
        status = zuptsdk_privkey_get_public(private_key, &key);
        unchanged = key == (zuptsdk_pubkey_t *)(uintptr_t)1;
        if (status == ZUPTSDK_OK) zuptsdk_pubkey_destroy(key);
    } else if (setup) {
        zuptsdk_keypair_t *pair = (zuptsdk_keypair_t *)(uintptr_t)1;
        status = zuptsdk_keypair_generate(NULL, &pair);
        unchanged = pair == (zuptsdk_keypair_t *)(uintptr_t)1;
        if (status == ZUPTSDK_OK) zuptsdk_keypair_destroy(pair);
    }
    char name[96];
    snprintf(name, sizeof(name), "%s %s collision preserves %s",
             derive ? "derive" : "keypair", public_collision ? "public" : "private",
             link_kind == 1 ? "symlink" : link_kind == 2 ? "hardlink" : "regular file");
    result(name, setup && status == ZUPTSDK_ERR_CRYPTO_FAIL && unchanged &&
                 same_file(collision_path, &before) && file_count() == 1 &&
                 live_allocs == allocations && descriptors() == handles);
    zuptsdk_privkey_destroy(private_key);
    (void)unlink(collision_path);
    if (link_kind) (void)unlink(target);
    clear_staging();
}

int main(void) {
    zuptsdk_allocator_t allocator = { test_malloc, test_free, test_realloc, NULL };
    if (zuptsdk_set_allocator(&allocator) != ZUPTSDK_OK) return 1;
    strcpy(root, "/tmp/zupt-sdk-key-ownership.XXXXXX");
    if (!mkdtemp(root)) return 1;
    snprintf(staging, sizeof(staging), "%s/staging", root);
    snprintf(private_path, sizeof(private_path), "%s/fixture.key", root);
    snprintf(public_path, sizeof(public_path), "%s/fixture.pub", root);
    if (mkdir(staging, 0700) != 0 || setenv("TMPDIR", staging, 1) != 0) return 1;

    zuptsdk_keypair_t *pair = NULL;
    int handles = descriptors();
    int setup = zuptsdk_keypair_generate(NULL, &pair) == ZUPTSDK_OK;
    setup = setup && file_count() == 2 &&
        zuptsdk_keypair_save_private(pair, private_path) == ZUPTSDK_OK &&
        zuptsdk_keypair_save_public(pair, public_path) == ZUPTSDK_OK;
    zuptsdk_keypair_destroy(pair);
    result("real keypair destruction removes both generated files",
           setup && file_count() == 0 && live_allocs == 0 && descriptors() == handles);
    if (!setup) return 1;

    for (size_t index = 1; index <= 3; ++index) allocation_failure(index, 0);
    for (size_t index = 1; index <= 2; ++index) allocation_failure(index, 1);

    for (int iteration = 0; iteration < 3; ++iteration) {
        zuptsdk_privkey_t *private_key = NULL;
        zuptsdk_pubkey_t *public_key = NULL;
        int ok = zuptsdk_privkey_load(private_path, &private_key) == ZUPTSDK_OK &&
            zuptsdk_privkey_get_public(private_key, &public_key) == ZUPTSDK_OK &&
            file_count() == 1;
        zuptsdk_pubkey_destroy(public_key);
        zuptsdk_privkey_destroy(private_key);
        result("derived public key destruction removes generated export",
               ok && file_count() == 0 && live_allocs == 0 && descriptors() == handles);
        clear_staging();
    }

    struct stat private_before, public_before;
    uint8_t private_bytes[4096], public_bytes[4096];
    size_t private_size = read_fixture(private_path, private_bytes, sizeof(private_bytes));
    size_t public_size = read_fixture(public_path, public_bytes, sizeof(public_bytes));
    zuptsdk_privkey_t *private_key = NULL;
    zuptsdk_pubkey_t *public_key = NULL;
    int loaded = private_size == 3664 && public_size == 1232 &&
        stat(private_path, &private_before) == 0 &&
        stat(public_path, &public_before) == 0 &&
        zuptsdk_privkey_load(private_path, &private_key) == ZUPTSDK_OK &&
        zuptsdk_pubkey_load(public_path, &public_key) == ZUPTSDK_OK;
    zuptsdk_privkey_destroy(private_key);
    zuptsdk_pubkey_destroy(public_key);
    struct stat after;
    loaded = loaded && stat(private_path, &after) == 0 &&
        after.st_dev == private_before.st_dev && after.st_ino == private_before.st_ino &&
        stat(public_path, &after) == 0 && after.st_dev == public_before.st_dev &&
        after.st_ino == public_before.st_ino &&
        fixture_matches(private_path, private_bytes, private_size) &&
        fixture_matches(public_path, public_bytes, public_size);
    result("destroying loaded keys preserves caller-owned files",
           loaded && live_allocs == 0 && descriptors() == handles);

    for (int link_kind = 0; link_kind <= 2; ++link_kind) {
        collision(0, link_kind, 0);
        collision(1, link_kind, 0);
        collision(1, link_kind, 1);
    }
    (void)unlink(private_path);
    (void)unlink(public_path);
    clear_staging();
    if (rmdir(staging) != 0 || rmdir(root) != 0) ++failures;
    printf("Key ownership: %d cases, %d failures\n", cases, failures);
    return failures ? 1 : 0;
}
