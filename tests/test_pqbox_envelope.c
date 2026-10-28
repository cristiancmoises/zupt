/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 */
#include "zupt.h"
#include "zupt_keccak.h"
#include "pqvaptvupt.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    TEST_KEY_HEADER_SIZE = 9,
    TEST_SEALED_SIZE = 1216,
    TEST_PAYLOAD_SIZE = 5 + TEST_SEALED_SIZE
};

static int make_secret_key(const char *path) {
    uint8_t key_file[TEST_KEY_HEADER_SIZE + PQVV_SECRETKEYBYTES] = {0};
    memcpy(key_file, "PQVVBOX1", 8);
    key_file[8] = 'S';

    FILE *file = fopen(path, "wbx");
    if (!file) return -1;
    int result = fwrite(key_file, 1, sizeof(key_file), file) == sizeof(key_file)
               ? 0 : -1;
    if (fclose(file) != 0) result = -1;
    if (result != 0) remove(path);
    return result;
}

static void make_payload(uint8_t payload[TEST_PAYLOAD_SIZE + 1]) {
    memset(payload, 0x5a, TEST_PAYLOAD_SIZE + 1);
    payload[0] = ZUPT_ENC_PQ_BOX_V1;
    payload[1] = 0xc0;
    payload[2] = 0x04;
    payload[3] = 0x00;
    payload[4] = 0x00;
}

static int expect_result(const char *name, int actual, int expected) {
    if (actual == expected) return 0;
    fprintf(stderr, "%s: expected %d, got %d\n", name, expected, actual);
    return 1;
}

int main(int argc, char **argv) {
    char key_path[512];
    uint8_t payload[TEST_PAYLOAD_SIZE + 1];
    zupt_keyring_t keyring;
    int failures = 0;

    const char *test_directory = argc > 1 ? argv[1] : ".";
    int written = snprintf(key_path, sizeof(key_path),
                           "%s/zupt-pqbox-envelope.key", test_directory);
    if (written < 0 || (size_t)written >= sizeof(key_path)) {
        fputs("pq-box key fixture path is too long\n", stderr);
        return 1;
    }

    if (make_secret_key(key_path) != 0) {
        perror("create pq-box key fixture");
        return 1;
    }
    make_payload(payload);

    memset(&keyring, 0, sizeof(keyring));
    failures += expect_result(
        "exact envelope",
        zupt_pqbox_decrypt_init(&keyring, key_path, payload,
                                TEST_PAYLOAD_SIZE),
        0);
    if (!keyring.active) {
        fputs("exact envelope: keyring was not activated\n", stderr);
        failures++;
    }
    zupt_secure_wipe(&keyring, sizeof(keyring));

    memset(&keyring, 0, sizeof(keyring));
    failures += expect_result(
        "trailing byte",
        zupt_pqbox_decrypt_init(&keyring, key_path, payload,
                                TEST_PAYLOAD_SIZE + 1),
        -1);
    if (keyring.active) {
        fputs("trailing byte: keyring was activated\n", stderr);
        failures++;
    }
    zupt_secure_wipe(&keyring, sizeof(keyring));

    memset(&keyring, 0, sizeof(keyring));
    failures += expect_result(
        "truncated envelope",
        zupt_pqbox_decrypt_init(&keyring, key_path, payload,
                                TEST_PAYLOAD_SIZE - 1),
        -1);

    zupt_secure_wipe(&keyring, sizeof(keyring));
    if (remove(key_path) != 0) {
        perror("remove pq-box key fixture");
        failures++;
    }

    if (failures != 0) return 1;
    puts("pq-box envelope length checks passed");
    return 0;
}

int pqvv_keygen(uint8_t pk[PQVV_PUBLICKEYBYTES],
                uint8_t sk[PQVV_SECRETKEYBYTES]) {
    memset(pk, 0, PQVV_PUBLICKEYBYTES);
    memset(sk, 0, PQVV_SECRETKEYBYTES);
    return PQVV_OK;
}

int pqvv_seal(const uint8_t pk[PQVV_PUBLICKEYBYTES],
              const uint8_t *pt, size_t pt_len,
              uint8_t **out, size_t *out_len) {
    (void)pk;
    (void)pt;
    (void)pt_len;
    *out = NULL;
    *out_len = 0;
    return PQVV_ERR_CORRUPT;
}

int pqvv_open(const uint8_t sk[PQVV_SECRETKEYBYTES],
              const uint8_t *ct, size_t ct_len,
              uint8_t **out, size_t *out_len) {
    (void)sk;
    (void)ct;
    if (ct_len != TEST_SEALED_SIZE) return PQVV_ERR_CORRUPT;

    *out = malloc(32);
    if (!*out) return PQVV_ERR_CORRUPT;
    memset(*out, 0x3c, 32);
    *out_len = 32;
    return PQVV_OK;
}

int zupt_keyfile_write_new(const char *path, const uint8_t *data,
                           size_t length, int private_material) {
    (void)path;
    (void)data;
    (void)length;
    (void)private_material;
    return -1;
}

void zupt_random_bytes(uint8_t *buffer, size_t length) {
    memset(buffer, 0xa5, length);
}

void zupt_sha3_256(const uint8_t *data, size_t length, uint8_t output[32]) {
    uint8_t accumulator = 0;
    for (size_t index = 0; index < length; index++) accumulator ^= data[index];
    memset(output, accumulator, 32);
}
