/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Exercise the native recipient-encryption header parsers with headers
 * produced by the matching encoders.  These payloads have fixed layouts;
 * accepting an extra suffix would leave unauthenticated bytes outside the
 * parsed envelope.
 */
#define _GNU_SOURCE
#include "zupt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*keygen_fn)(const char *);
typedef int (*export_fn)(const char *, const char *);
typedef int (*encrypt_fn)(zupt_keyring_t *, const char *, uint8_t *, size_t *);
typedef int (*decrypt_fn)(zupt_keyring_t *, const char *, const uint8_t *, size_t);

static int failures;

static int check(int condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
    } else {
        fprintf(stderr, "FAIL: %s\n", message);
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

static void exercise_mode(const char *label, const char *path_prefix,
                          size_t expected_length, uint8_t expected_type,
                          keygen_fn keygen, export_fn export_public,
                          encrypt_fn encrypt, decrypt_fn decrypt) {
    char private_path[512];
    char public_path[512];
    uint8_t header[1501];
    zupt_keyring_t encrypt_keyring;
    zupt_keyring_t decrypt_keyring;
    size_t header_length = 0;
    int private_created = 0;
    int public_created = 0;

    zupt_keyring_init(&encrypt_keyring);
    zupt_keyring_init(&decrypt_keyring);

    int private_written = snprintf(private_path, sizeof(private_path),
                                   "%s-%s-private.key", path_prefix, label);
    int public_written = snprintf(public_path, sizeof(public_path),
                                  "%s-%s-public.key", path_prefix, label);
    if (private_written < 0 || (size_t)private_written >= sizeof(private_path) ||
        public_written < 0 || (size_t)public_written >= sizeof(public_path)) {
        fprintf(stderr, "FAIL: %s temporary path overflow\n", label);
        failures++;
        return;
    }

    if (!check(keygen(private_path) == 0,
               "native private key generation succeeds")) {
        goto cleanup;
    }
    private_created = 1;
    if (!check(export_public(private_path, public_path) == 0,
               "native public key export succeeds")) {
        goto cleanup;
    }
    public_created = 1;

    memset(header, 0, sizeof(header));
    if (!check(encrypt(&encrypt_keyring, public_path, header,
                       &header_length) == 0,
               "native envelope generation succeeds")) {
        goto cleanup;
    }
    if (!check(header_length == expected_length,
               "native encoder emits its fixed envelope length")) {
        goto cleanup;
    }
    check(header[0] == expected_type,
          "native encoder emits the expected envelope type");

    zupt_keyring_init(&decrypt_keyring);
    check(decrypt(&decrypt_keyring, private_path, header, header_length) == 0,
          "native decoder accepts the exact encoder output");
    clear_keyring(&decrypt_keyring);

    zupt_keyring_init(&decrypt_keyring);
    check(decrypt(&decrypt_keyring, private_path, header, header_length - 1) != 0,
          "native decoder rejects a truncated envelope");
    clear_keyring(&decrypt_keyring);

    header[header_length] = 0xa5;
    zupt_keyring_init(&decrypt_keyring);
    check(decrypt(&decrypt_keyring, private_path, header, header_length + 1) != 0,
          "native decoder rejects a trailing envelope byte");
    clear_keyring(&decrypt_keyring);

    header[0] ^= 0xff;
    zupt_keyring_init(&decrypt_keyring);
    check(decrypt(&decrypt_keyring, private_path, header, header_length) != 0,
          "native decoder rejects the wrong envelope type");
    clear_keyring(&decrypt_keyring);

cleanup:
    clear_keyring(&decrypt_keyring);
    clear_keyring(&encrypt_keyring);
    if (public_created && remove(public_path) != 0) {
        fprintf(stderr, "FAIL: could not remove %s public key\n", label);
        failures++;
    }
    if (private_created && remove(private_path) != 0) {
        fprintf(stderr, "FAIL: could not remove %s private key\n", label);
        failures++;
    }
}

int main(int argc, char **argv) {
    char path_prefix[512];
    const char *test_directory = argc > 1 ? argv[1] : ".";
    int written = snprintf(path_prefix, sizeof(path_prefix),
                           "%s/zupt-native-envelope", test_directory);
    if (written < 0 || (size_t)written >= sizeof(path_prefix)) {
        fputs("FAIL: temporary path prefix overflow\n", stderr);
        return 1;
    }

    exercise_mode("hybrid", path_prefix, 1u + 1088u + 32u + 16u,
                  ZUPT_ENC_PQ_HYBRID, zupt_hybrid_keygen,
                  zupt_hybrid_export_pubkey, zupt_hybrid_encrypt_init,
                  zupt_hybrid_decrypt_init);
    exercise_mode("pq-only", path_prefix, 1u + 1088u + 16u,
                  ZUPT_ENC_PQ_ONLY, zupt_pq_keygen, zupt_pq_export_pubkey,
                  zupt_pq_encrypt_init, zupt_pq_decrypt_init);

    if (failures != 0) {
        fprintf(stderr, "native envelope tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("native envelope tests: PASS");
    return 0;
}
