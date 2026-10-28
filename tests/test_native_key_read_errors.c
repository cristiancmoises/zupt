/* SPDX-License-Identifier: AGPL-3.0-or-later */
#define _GNU_SOURCE 1
#include "zupt.h"
#include <stdio.h>

/* Linux glibc and musl cookie streams give this test real EOF/error flags
 * without exposing a production-only test API. Other targets keep the normal
 * key tests; Windows also uses a different file-opening entry point. */
#if defined(__linux__) && !defined(__ANDROID__)

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

FILE *__real_fopen(const char *, const char *);
FILE *__wrap_fopen(const char *, const char *);
size_t __real_fread(void *, size_t, size_t, FILE *);
size_t __wrap_fread(void *, size_t, size_t, FILE *);
int __real_fgetc(FILE *);
int __wrap_fgetc(FILE *);
int __real_fclose(FILE *);
int __wrap_fclose(FILE *);

typedef int (*keygen_fn)(const char *);
typedef int (*export_fn)(const char *, const char *);
typedef int (*encrypt_fn)(zupt_keyring_t *, const char *, uint8_t *, size_t *);
typedef int (*decrypt_fn)(zupt_keyring_t *, const char *, const uint8_t *, size_t);

enum operation { ENCRYPT, DECRYPT, EXPORT };
struct mode {
    const char *name;
    size_t public_size, private_size;
    keygen_fn keygen;
    export_fn export_public;
    encrypt_fn encrypt;
    decrypt_fn decrypt;
};
struct read_case {
    const char *name;
    int private_key, read_error, close_error, junk, malformed;
    size_t limit;
    int success, probes, eof_after_read, error_after_read;
};
struct key_stream {
    const uint8_t *data;
    size_t length, position;
    int read_error, close_error;
};

static struct key_stream cookie;
static FILE *key_stream;
static const char *selected_path;
static int injecting, opens, reads, probes, bad_probes, closes, cookie_closes;
static int eof_after_read, error_after_read;
static size_t length_after_read;
static int failures, cases;

static ssize_t cookie_read(void *context, char *buffer, size_t capacity) {
    struct key_stream *input = context;
    if (input->position < input->length) {
        size_t length = input->length - input->position;
        if (length > capacity) length = capacity;
        memcpy(buffer, input->data + input->position, length);
        input->position += length;
        return (ssize_t)length;
    }
    if (input->read_error) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int cookie_close(void *context) {
    struct key_stream *input = context;
    cookie_closes++;
    if (input->close_error) {
        errno = EIO;
        return -1;
    }
    return 0;
}

FILE *__wrap_fopen(const char *path, const char *mode) {
    if (injecting && strcmp(path, selected_path) == 0 && strcmp(mode, "rb") == 0) {
        cookie_io_functions_t functions = {cookie_read, NULL, NULL, cookie_close};
        opens++;
        key_stream = fopencookie(&cookie, "rb", functions);
        return key_stream;
    }
    return __real_fopen(path, mode);
}

size_t __wrap_fread(void *buffer, size_t size, size_t count, FILE *stream) {
    size_t result = __real_fread(buffer, size, count, stream);
    if (injecting && stream == key_stream) {
        reads++;
        length_after_read = result;
        eof_after_read = feof(stream) != 0;
        error_after_read = ferror(stream) != 0;
    }
    return result;
}

int __wrap_fgetc(FILE *stream) {
    if (injecting && stream == key_stream) {
        probes++;
        if (ferror(stream) || feof(stream)) bad_probes++;
    }
    return __real_fgetc(stream);
}

int __wrap_fclose(FILE *stream) {
    if (injecting && stream == key_stream) {
        closes++;
        key_stream = NULL;
    }
    return __real_fclose(stream);
}

static int check(int condition, const char *mode, const char *name,
                 const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s / %s: %s\n", mode, name, message);
        failures++;
    }
    return condition;
}

static void clear_keyring(zupt_keyring_t *keyring) {
    if (keyring->active) {
        zupt_munlock_keys(keyring->enc_key, sizeof(keyring->enc_key));
        zupt_munlock_keys(keyring->mac_key, sizeof(keyring->mac_key));
    }
    zupt_secure_wipe(keyring, sizeof(*keyring));
}

static int load_fixture(const char *path, uint8_t *data, size_t length) {
    FILE *stream = fopen(path, "rb");
    if (!stream) return -1;
    int failed = fread(data, 1, length, stream) != length;
    if (fclose(stream) != 0) failed = 1;
    return failed ? -1 : 0;
}

static void exercise_case(const struct mode *mode, const struct read_case *test,
                          enum operation operation, const char *private_path,
                          const char *public_path, const char *output_path,
                          const uint8_t *private_data, const uint8_t *public_data,
                          const uint8_t *valid_header, size_t valid_header_length) {
    uint8_t data[3700], header[1137], original_header[1137];
    zupt_keyring_t keyring, original_keyring;
    size_t length = test->private_key ? mode->private_size : mode->public_size;
    const char *operation_name = operation == ENCRYPT ? "encrypt" :
                                 operation == DECRYPT ? "decrypt" : "export";
    char name[160];
    snprintf(name, sizeof(name), "%s / %s", test->name, operation_name);
    cases++;
    int previous_failures = failures;
    memcpy(data, test->private_key ? private_data : public_data, length);
    if (test->malformed == 1) data[6] = 1;
    if (test->malformed == 2) data[length - 1] ^= 1;
    if (test->junk) data[length++] = 0xa5;
    if (test->limit && test->limit < length) length = test->limit;
    cookie = (struct key_stream){data, length, 0, test->read_error, test->close_error};
    selected_path = test->private_key ? private_path : public_path;
    opens = reads = probes = bad_probes = closes = cookie_closes = 0;
    eof_after_read = error_after_read = 0;
    length_after_read = 0;
    zupt_keyring_init(&keyring);
    original_keyring = keyring;
    memset(header, 0xa5, sizeof(header));
    memcpy(original_header, header, sizeof(header));
    size_t header_length = 12345;
    injecting = 1;
    errno = 0;
    int result;
    if (operation == ENCRYPT)
        result = mode->encrypt(&keyring, selected_path, header, &header_length);
    else if (operation == DECRYPT)
        result = mode->decrypt(&keyring, selected_path, valid_header, valid_header_length);
    else
        result = mode->export_public(selected_path, output_path);
    int saved_errno = errno;
    injecting = 0;

    int success = test->success && (operation == ENCRYPT || test->private_key);
    check(success ? result == 0 : result == -1, mode->name, name, "reader result");
    if (!success) {
        check(saved_errno == EINVAL, mode->name, name, "read or format rejection keeps EINVAL");
        check(memcmp(&keyring, &original_keyring, sizeof(keyring)) == 0,
              mode->name, name, "rejection preserves caller keyring");
        check(memcmp(header, original_header, sizeof(header)) == 0 && header_length == 12345,
              mode->name, name, "rejection preserves caller header and length");
        if (operation == EXPORT)
            check(access(output_path, F_OK) != 0, mode->name, name, "rejection creates no output");
    }
    check(opens == 1 && reads == 1, mode->name, name, "real reader opens and reads selected path once");
    check(probes == test->probes && bad_probes == 0, mode->name, name,
          "trailing probe occurs only before EOF or read error");
    check(eof_after_read == test->eof_after_read && error_after_read == test->error_after_read,
          mode->name, name, "cookie establishes expected real stream flags");
    if (test->read_error && test->limit)
        check(length_after_read == test->limit, mode->name, name, "fread returns positive bytes with error set");
    check(closes == 1 && cookie_closes == 1 && key_stream == NULL,
          mode->name, name, "reader closes cookie exactly once");
    if (key_stream) {
        __real_fclose(key_stream);
        key_stream = NULL;
    }
    if (success && operation == EXPORT) {
        uint8_t exported[1232];
        check(load_fixture(output_path, exported, mode->public_size) == 0 &&
              memcmp(exported, public_data, mode->public_size) == 0,
              mode->name, name, "valid private key exports original public bytes");
        check(remove(output_path) == 0, mode->name, name, "remove successful export");
    }
    if (operation == EXPORT) {
        if (access(output_path, F_OK) == 0)
            check(remove(output_path) == 0, mode->name, name, "remove unexpected export after failure");
        check(access(output_path, F_OK) != 0, mode->name, name, "export case leaves no file behind");
    }
    if (success && operation == ENCRYPT) {
        zupt_keyring_t decrypted;
        zupt_keyring_init(&decrypted);
        check(mode->decrypt(&decrypted, private_path, header, header_length) == 0 &&
              memcmp(keyring.enc_key, decrypted.enc_key, 32) == 0 &&
              memcmp(keyring.mac_key, decrypted.mac_key, 32) == 0,
              mode->name, name, "accepted key encrypts with matching private key");
        clear_keyring(&decrypted);
    }
    clear_keyring(&keyring);
    if (failures == previous_failures) printf("PASS: %s / %s\n", mode->name, name);
}

static void exercise_mode(const struct mode *mode, const char *directory) {
    char private_path[512], public_path[512], output_path[512];
    uint8_t private_data[3696], public_data[1232], header[1137];
    zupt_keyring_t keyring;
    size_t header_length = 0;
    int private_created = 0, public_created = 0;
    zupt_keyring_init(&keyring);
    snprintf(private_path, sizeof(private_path), "%s/%s-private.key", directory, mode->name);
    snprintf(public_path, sizeof(public_path), "%s/%s-public.key", directory, mode->name);
    snprintf(output_path, sizeof(output_path), "%s/%s-export.key", directory, mode->name);
    if (!check(mode->keygen(private_path) == 0, mode->name, "fixture", "real private key generation"))
        goto cleanup;
    private_created = 1;
    if (!check(mode->export_public(private_path, public_path) == 0,
               mode->name, "fixture", "real public export")) goto cleanup;
    public_created = 1;
    if (!check(load_fixture(private_path, private_data, mode->private_size) == 0 &&
               load_fixture(public_path, public_data, mode->public_size) == 0,
               mode->name, "fixture", "read generated fixture bytes")) goto cleanup;
    if (!check(mode->encrypt(&keyring, public_path, header, &header_length) == 0,
               mode->name, "fixture", "real valid encryption header")) goto cleanup;
    clear_keyring(&keyring);

    const struct read_case tests[] = {
        {"public EOF", 0, 0, 0, 0, 0, 0, 1, 0, 1, 0},
        {"private exact size", 1, 0, 0, 0, 0, 0, 1, 1, 0, 0},
        {"positive public-sized read then error", 0, 1, 0, 0, 0, mode->public_size, 0, 0, 0, 1},
        {"positive truncated read then error", 1, 1, 0, 0, 0, 13, 0, 0, 0, 1},
        {"private trailing byte", 1, 0, 0, 1, 0, 0, 0, 1, 0, 0},
        {"private trailing read error", 1, 1, 0, 0, 0, 0, 0, 1, 0, 0},
        {"public close failure", 0, 0, 1, 0, 0, 0, 0, 0, 1, 0},
        {"private close failure", 1, 0, 1, 0, 0, 0, 0, 1, 0, 0},
        {"public reserved header", 0, 0, 0, 0, 1, 0, 0, 0, 1, 0},
        {"private checksum", 1, 0, 0, 0, 2, 0, 0, 1, 0, 0},
        {"truncated private EOF", 1, 0, 0, 0, 0, 13, 0, 0, 1, 0}
    };
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        for (enum operation operation = ENCRYPT; operation <= EXPORT; operation++)
            exercise_case(mode, &tests[i], operation, private_path, public_path, output_path,
                          private_data, public_data, header, header_length);
    }
cleanup:
    clear_keyring(&keyring);
    if (public_created)
        check(remove(public_path) == 0, mode->name, "cleanup", "remove generated public fixture");
    if (private_created)
        check(remove(private_path) == 0, mode->name, "cleanup", "remove generated private fixture");
    zupt_secure_wipe(private_data, sizeof(private_data));
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const struct mode modes[] = {
        {"ZKEY", 1232, 3664, zupt_hybrid_keygen, zupt_hybrid_export_pubkey,
         zupt_hybrid_encrypt_init, zupt_hybrid_decrypt_init},
        {"ZPQK", 1200, 3600, zupt_pq_keygen, zupt_pq_export_pubkey,
         zupt_pq_encrypt_init, zupt_pq_decrypt_init}
    };
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
        exercise_mode(&modes[i], argv[1]);
    printf("native key read errors: %d cases, %d failures\n", cases, failures);
    return failures ? 1 : 0;
}

#else
int main(void) {
    puts("SKIP: native key read fault injection requires GNU/Linux cookie streams and fopen wrapping");
    return 0;
}
#endif
