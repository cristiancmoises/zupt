/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Exercise the real SDK adapter against a controlled provider boundary.
 */
#include "zupt.h"
#include "zupt_keccak.h"
#include "sdk_adapter_stubs/zuptsdk_easy.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_HEADER_CAPACITY 1500u
#define TEST_BLOB_CAPACITY   1496u
#define TEST_LENGTH_SENTINEL ((size_t)0x5a17c0deu)

struct zuptsdk_ctx {
    int unused;
};

struct zuptsdk_keypair {
    int unused;
};

static uint8_t provider_blob[TEST_BLOB_CAPACITY];
static uint8_t provider_plaintext[64];
static int encrypt_result;
static size_t encrypt_blob_size;
static int encrypt_returns_blob;
static int decrypt_result;
static size_t decrypt_plaintext_size;
static int decrypt_returns_plaintext;

static uintptr_t encrypt_session_address;
static size_t encrypt_calls;
static size_t decrypt_calls;
static size_t decrypt_input_size;
static size_t sdk_blob_frees;
static size_t sdk_plaintext_frees;
static size_t unexpected_sdk_frees;
static size_t forbidden_libc_frees;
static size_t rejected_copies;
static size_t encrypt_session_wipes;
static size_t sdk_plaintext_wipes;
static size_t sdk_plaintext_wipe_size;
static int encrypt_session_wiped_to_zero;

static int failures;

void forbidden_libc_free(void *pointer);

static void fail(const char *case_name, const char *message)
{
    fprintf(stderr, "FAIL: %s: %s\n", case_name, message);
    failures++;
}

static void reset_provider(void)
{
    for (size_t i = 0; i < sizeof(provider_blob); i++)
        provider_blob[i] = (uint8_t)(0x30u + (i & 0x3fu));
    memset(provider_plaintext, 0x3c, sizeof(provider_plaintext));

    encrypt_result = 0;
    encrypt_blob_size = 8;
    encrypt_returns_blob = 1;
    decrypt_result = 0;
    decrypt_plaintext_size = 32;
    decrypt_returns_plaintext = 1;

    encrypt_session_address = 0;
    encrypt_calls = 0;
    decrypt_calls = 0;
    decrypt_input_size = 0;
    sdk_blob_frees = 0;
    sdk_plaintext_frees = 0;
    unexpected_sdk_frees = 0;
    forbidden_libc_frees = 0;
    rejected_copies = 0;
    encrypt_session_wipes = 0;
    sdk_plaintext_wipes = 0;
    sdk_plaintext_wipe_size = 0;
    encrypt_session_wiped_to_zero = 0;
}

static void initialize_failure_outputs(zupt_keyring_t *keyring,
                                       uint8_t header[TEST_HEADER_CAPACITY],
                                       size_t *header_length,
                                       zupt_keyring_t *keyring_before,
                                       uint8_t header_before[TEST_HEADER_CAPACITY])
{
    memset(keyring, 0x91, sizeof(*keyring));
    memset(header, 0x6d, TEST_HEADER_CAPACITY);
    *header_length = TEST_LENGTH_SENTINEL;
    memcpy(keyring_before, keyring, sizeof(*keyring));
    memcpy(header_before, header, TEST_HEADER_CAPACITY);
}

static void check_failure_outputs(const char *case_name,
                                  const zupt_keyring_t *keyring,
                                  const uint8_t header[TEST_HEADER_CAPACITY],
                                  size_t header_length,
                                  const zupt_keyring_t *keyring_before,
                                  const uint8_t header_before[TEST_HEADER_CAPACITY])
{
    if (header_length != TEST_LENGTH_SENTINEL)
        fail(case_name, "changed the caller's output length on failure");
    if (memcmp(keyring, keyring_before, sizeof(*keyring)) != 0)
        fail(case_name, "changed the keyring on failure");
    if (memcmp(header, header_before, TEST_HEADER_CAPACITY) != 0)
        fail(case_name, "changed the output header on failure");
    if (encrypt_session_wipes != 1 || !encrypt_session_wiped_to_zero)
        fail(case_name, "did not wipe the generated session key");
}

int zuptsdk_ctx_create(zuptsdk_ctx_t **ctx_out)
{
    (void)ctx_out;
    return -1;
}

void zuptsdk_ctx_destroy(zuptsdk_ctx_t *ctx)
{
    (void)ctx;
}

int zuptsdk_keypair_generate(zuptsdk_ctx_t *ctx,
                             zuptsdk_keypair_t **keypair_out)
{
    (void)ctx;
    (void)keypair_out;
    return -1;
}

int zuptsdk_keypair_save_private(const zuptsdk_keypair_t *keypair,
                                 const char *path)
{
    (void)keypair;
    (void)path;
    return -1;
}

int zuptsdk_keypair_save_public(const zuptsdk_keypair_t *keypair,
                                const char *path)
{
    (void)keypair;
    (void)path;
    return -1;
}

void zuptsdk_keypair_destroy(zuptsdk_keypair_t *keypair)
{
    (void)keypair;
}

int zuptsdk_easy_encrypt(const char *recipient_pubkey_path,
                         const uint8_t *plaintext, size_t plaintext_size,
                         uint8_t **blob_out, size_t *blob_size)
{
    (void)recipient_pubkey_path;
    encrypt_calls++;
    encrypt_session_address = (uintptr_t)plaintext;
    if (plaintext_size != 32)
        failures++;
    *blob_out = encrypt_returns_blob ? provider_blob : NULL;
    *blob_size = encrypt_blob_size;
    return encrypt_result;
}

int zuptsdk_easy_decrypt(const char *recipient_privkey_path,
                         const uint8_t *blob, size_t blob_size,
                         uint8_t **plaintext_out, size_t *plaintext_size)
{
    (void)recipient_privkey_path;
    if (!blob)
        failures++;
    decrypt_calls++;
    decrypt_input_size = blob_size;
    *plaintext_out = decrypt_returns_plaintext ? provider_plaintext : NULL;
    *plaintext_size = decrypt_plaintext_size;
    return decrypt_result;
}

int zuptsdk_easy_derive_key(const char *password, const uint8_t salt[16],
                            uint8_t key_out[32])
{
    (void)password;
    (void)salt;
    memset(key_out, 0x42, 32);
    return 0;
}

int zuptsdk_easy_random_salt(uint8_t salt_out[16])
{
    memset(salt_out, 0x24, 16);
    return 0;
}

void zuptsdk_free(void *pointer)
{
    if (pointer == provider_blob)
        sdk_blob_frees++;
    else if (pointer == provider_plaintext)
        sdk_plaintext_frees++;
    else
        unexpected_sdk_frees++;
}

void zuptsdk_secure_zero(void *buffer, size_t bytes)
{
    volatile uint8_t *cursor = buffer;
    if (buffer == provider_plaintext) {
        sdk_plaintext_wipes++;
        sdk_plaintext_wipe_size = bytes;
    }
    for (size_t i = 0; i < bytes; i++)
        cursor[i] = 0;
}

void zupt_random_bytes(uint8_t *buffer, size_t bytes)
{
    memset(buffer, 0xa5, bytes);
}

void zupt_sha3_256(const uint8_t *input, size_t input_size,
                   uint8_t output[32])
{
    uint8_t accumulator = 0;
    for (size_t i = 0; i < input_size; i++)
        accumulator ^= input[i];
    memset(output, accumulator, 32);
}

static void observed_secure_wipe(void *buffer, size_t bytes)
{
    volatile uint8_t *cursor = buffer;
    if ((uintptr_t)buffer == encrypt_session_address && bytes == 32)
        encrypt_session_wipes++;
    for (size_t i = 0; i < bytes; i++)
        cursor[i] = 0;
    if ((uintptr_t)buffer == encrypt_session_address && bytes == 32) {
        encrypt_session_wiped_to_zero = 1;
        for (size_t i = 0; i < bytes; i++) {
            if (cursor[i] != 0)
                encrypt_session_wiped_to_zero = 0;
        }
    }
}

void forbidden_libc_free(void *pointer)
{
    (void)pointer;
    forbidden_libc_frees++;
}

static void *checked_memcpy(void *destination, const void *source, size_t bytes)
{
    if ((source == provider_blob &&
         bytes > TEST_HEADER_CAPACITY - 5u) ||
        bytes > TEST_HEADER_CAPACITY) {
        rejected_copies++;
        return destination;
    }
    return memcpy(destination, source, bytes);
}

#define free forbidden_libc_free
#define memcpy checked_memcpy
#define zupt_secure_wipe observed_secure_wipe
#include "../src/zupt_crypto_sdk.c"
#undef zupt_secure_wipe
#undef memcpy
#undef free

static void test_encrypt_success(void)
{
    static const char case_name[] = "encrypt success ownership";
    zupt_keyring_t keyring;
    uint8_t header[TEST_HEADER_CAPACITY];
    size_t header_length = 0;

    reset_provider();
    memset(&keyring, 0, sizeof(keyring));
    memset(header, 0, sizeof(header));
    if (zupt_sdk_hybrid_encrypt_init(&keyring, "recipient.pub", header,
                                     &header_length) != 0)
        fail(case_name, "rejected a valid provider result");
    if (header_length != 13 || header[0] != ZUPT_ENC_PQ_SDK_V2 ||
        header[1] != 8 || header[2] != 0 || header[3] != 0 ||
        header[4] != 0 || memcmp(header + 5, provider_blob, 8) != 0)
        fail(case_name, "did not serialize the exact provider blob");
    if (encrypt_calls != 1 || sdk_blob_frees != 1 ||
        forbidden_libc_frees != 0 || unexpected_sdk_frees != 0)
        fail(case_name, "did not release the provider blob with zuptsdk_free");
    if (encrypt_session_wipes != 1 || !encrypt_session_wiped_to_zero)
        fail(case_name, "did not wipe the generated session key");
    if (!keyring.active || keyring.canary_head != ZUPT_CANARY ||
        keyring.canary_tail != ZUPT_CANARY)
        fail(case_name, "did not initialize the keyring");
    zupt_secure_wipe(&keyring, sizeof(keyring));
}

static void test_encrypt_provider_error_with_blob(void)
{
    static const char case_name[] = "encrypt provider error ownership";
    zupt_keyring_t keyring;
    zupt_keyring_t keyring_before;
    uint8_t header[TEST_HEADER_CAPACITY];
    uint8_t header_before[TEST_HEADER_CAPACITY];
    size_t header_length;

    reset_provider();
    encrypt_result = -7;
    initialize_failure_outputs(&keyring, header, &header_length,
                               &keyring_before, header_before);
    if (zupt_sdk_hybrid_encrypt_init(&keyring, "recipient.pub", header,
                                     &header_length) == 0)
        fail(case_name, "accepted a provider error");
    check_failure_outputs(case_name, &keyring, header, header_length,
                          &keyring_before, header_before);
    if (sdk_blob_frees != 0 || forbidden_libc_frees != 0 ||
        unexpected_sdk_frees != 0)
        fail(case_name, "used untrusted provider outputs after an error");
}

static void test_encrypt_maximum_blob(void)
{
    static const char case_name[] = "encrypt maximum-size blob";
    zupt_keyring_t keyring;
    uint8_t header[TEST_HEADER_CAPACITY];
    size_t header_length = 0;

    reset_provider();
    encrypt_blob_size = TEST_HEADER_CAPACITY - 5;
    memset(&keyring, 0, sizeof(keyring));
    memset(header, 0, sizeof(header));
    if (zupt_sdk_hybrid_encrypt_init(&keyring, "recipient.pub", header,
                                     &header_length) != 0)
        fail(case_name, "rejected the largest valid provider blob");
    if (header_length != TEST_HEADER_CAPACITY ||
        header[TEST_HEADER_CAPACITY - 1] !=
            provider_blob[TEST_BLOB_CAPACITY - 2])
        fail(case_name, "did not serialize the complete boundary blob");
    if (sdk_blob_frees != 1 || forbidden_libc_frees != 0 ||
        unexpected_sdk_frees != 0)
        fail(case_name, "did not release the boundary blob correctly");
    if (encrypt_session_wipes != 1 || !encrypt_session_wiped_to_zero)
        fail(case_name, "did not wipe the generated session key");
}

static void test_encrypt_null_blob(void)
{
    static const char case_name[] = "encrypt null provider output";
    zupt_keyring_t keyring;
    zupt_keyring_t keyring_before;
    uint8_t header[TEST_HEADER_CAPACITY];
    uint8_t header_before[TEST_HEADER_CAPACITY];
    size_t header_length;

    reset_provider();
    encrypt_returns_blob = 0;
    initialize_failure_outputs(&keyring, header, &header_length,
                               &keyring_before, header_before);
    if (zupt_sdk_hybrid_encrypt_init(&keyring, "recipient.pub", header,
                                     &header_length) == 0)
        fail(case_name, "accepted a NULL provider output");
    check_failure_outputs(case_name, &keyring, header, header_length,
                          &keyring_before, header_before);
    if (sdk_blob_frees != 0 || forbidden_libc_frees != 0 ||
        unexpected_sdk_frees != 0)
        fail(case_name, "released a pointer the provider did not return");
}

static void test_encrypt_zero_length_blob(void)
{
    static const char case_name[] = "encrypt zero-length provider blob";
    zupt_keyring_t keyring;
    zupt_keyring_t keyring_before;
    uint8_t header[TEST_HEADER_CAPACITY];
    uint8_t header_before[TEST_HEADER_CAPACITY];
    size_t header_length;

    reset_provider();
    encrypt_blob_size = 0;
    initialize_failure_outputs(&keyring, header, &header_length,
                               &keyring_before, header_before);
    if (zupt_sdk_hybrid_encrypt_init(&keyring, "recipient.pub", header,
                                     &header_length) == 0)
        fail(case_name, "accepted an empty provider blob");
    check_failure_outputs(case_name, &keyring, header, header_length,
                          &keyring_before, header_before);
    if (sdk_blob_frees != 1 || forbidden_libc_frees != 0 ||
        unexpected_sdk_frees != 0)
        fail(case_name, "did not release the empty provider blob correctly");
}

static void test_encrypt_oversize(size_t blob_size, const char *case_name)
{
    zupt_keyring_t keyring;
    zupt_keyring_t keyring_before;
    uint8_t header[TEST_HEADER_CAPACITY];
    uint8_t header_before[TEST_HEADER_CAPACITY];
    size_t header_length;

    reset_provider();
    encrypt_blob_size = blob_size;
    initialize_failure_outputs(&keyring, header, &header_length,
                               &keyring_before, header_before);
    if (zupt_sdk_hybrid_encrypt_init(&keyring, "recipient.pub", header,
                                     &header_length) == 0)
        fail(case_name, "accepted a blob that cannot fit the envelope");
    check_failure_outputs(case_name, &keyring, header, header_length,
                          &keyring_before, header_before);
    if (sdk_blob_frees != 1 || forbidden_libc_frees != 0 ||
        unexpected_sdk_frees != 0)
        fail(case_name, "did not release the rejected provider blob correctly");
    if (rejected_copies != 0)
        fail(case_name, "attempted a copy before rejecting the provider length");
}

static void write_declared_size(uint8_t header[static 5],
                                uint32_t blob_size)
{
    header[0] = ZUPT_ENC_PQ_SDK_V2;
    header[1] = (uint8_t)(blob_size & 0xffu);
    header[2] = (uint8_t)((blob_size >> 8) & 0xffu);
    header[3] = (uint8_t)((blob_size >> 16) & 0xffu);
    header[4] = (uint8_t)((blob_size >> 24) & 0xffu);
}

static void test_decrypt_exact_envelope(void)
{
    static const char case_name[] = "decrypt exact envelope";
    zupt_keyring_t keyring;
    uint8_t header[TEST_HEADER_CAPACITY];

    reset_provider();
    memset(&keyring, 0, sizeof(keyring));
    memset(header, 0, sizeof(header));
    write_declared_size(header, 8);
    memcpy(header + 5, provider_blob, 8);
    if (zupt_sdk_hybrid_decrypt_init(&keyring, "recipient.key", header, 13) != 0)
        fail(case_name, "rejected an exact valid envelope");
    if (decrypt_calls != 1 || decrypt_input_size != 8)
        fail(case_name, "did not pass the exact blob to the provider");
    if (sdk_plaintext_wipes != 1 || sdk_plaintext_wipe_size != 32 ||
        sdk_plaintext_frees != 1 ||
        unexpected_sdk_frees != 0)
        fail(case_name, "did not wipe and release the recovered key");
    if (!keyring.active || keyring.canary_head != ZUPT_CANARY ||
        keyring.canary_tail != ZUPT_CANARY)
        fail(case_name, "did not initialize the keyring");
    zupt_secure_wipe(&keyring, sizeof(keyring));
}

static void test_decrypt_provider_error_with_plaintext(void)
{
    static const char case_name[] = "decrypt provider error ownership";
    zupt_keyring_t keyring;
    zupt_keyring_t keyring_before;
    uint8_t header[13] = {0};

    reset_provider();
    decrypt_result = -7;
    memset(&keyring, 0x29, sizeof(keyring));
    keyring_before = keyring;
    write_declared_size(header, 8);
    memcpy(header + 5, provider_blob, 8);
    if (zupt_sdk_hybrid_decrypt_init(&keyring, "recipient.key", header,
                                     sizeof(header)) == 0)
        fail(case_name, "accepted a provider error");
    if (decrypt_calls != 1)
        fail(case_name, "did not call the provider exactly once");
    if (sdk_plaintext_wipes != 0 || sdk_plaintext_frees != 0 ||
        unexpected_sdk_frees != 0)
        fail(case_name, "used untrusted provider outputs after an error");
    if (memcmp(&keyring, &keyring_before, sizeof(keyring)) != 0)
        fail(case_name, "changed the keyring after a provider error");
}

static void test_decrypt_maximum_blob(void)
{
    static const char case_name[] = "decrypt maximum-size blob";
    zupt_keyring_t keyring;
    uint8_t header[TEST_HEADER_CAPACITY];

    reset_provider();
    memset(&keyring, 0, sizeof(keyring));
    memset(header, 0, sizeof(header));
    write_declared_size(header, TEST_HEADER_CAPACITY - 5);
    memcpy(header + 5, provider_blob, TEST_HEADER_CAPACITY - 5);
    if (zupt_sdk_hybrid_decrypt_init(&keyring, "recipient.key", header,
                                     sizeof(header)) != 0)
        fail(case_name, "rejected the largest valid envelope");
    if (decrypt_calls != 1 ||
        decrypt_input_size != TEST_HEADER_CAPACITY - 5)
        fail(case_name, "did not pass the complete boundary blob");
    if (sdk_plaintext_wipes != 1 || sdk_plaintext_wipe_size != 32 ||
        sdk_plaintext_frees != 1 || unexpected_sdk_frees != 0)
        fail(case_name, "did not wipe and release the recovered key");
    if (!keyring.active)
        fail(case_name, "did not activate the keyring");
    zupt_secure_wipe(&keyring, sizeof(keyring));
}

static void test_decrypt_wrong_plaintext_size(void)
{
    static const char case_name[] = "decrypt wrong plaintext size";
    zupt_keyring_t keyring;
    zupt_keyring_t keyring_before;
    uint8_t header[13] = {0};

    reset_provider();
    decrypt_plaintext_size = sizeof(provider_plaintext);
    memset(&keyring, 0x39, sizeof(keyring));
    keyring_before = keyring;
    write_declared_size(header, 8);
    memcpy(header + 5, provider_blob, 8);
    if (zupt_sdk_hybrid_decrypt_init(&keyring, "recipient.key", header,
                                     sizeof(header)) == 0)
        fail(case_name, "accepted a non-session-key plaintext size");
    if (decrypt_calls != 1)
        fail(case_name, "did not call the provider exactly once");
    if (sdk_plaintext_wipes != 0 || sdk_plaintext_frees != 1 ||
        unexpected_sdk_frees != 0)
        fail(case_name, "traversed an invalid plaintext length");
    if (memcmp(&keyring, &keyring_before, sizeof(keyring)) != 0)
        fail(case_name, "changed the keyring for an invalid plaintext size");
}

static void test_decrypt_rejects_trailing_byte(void)
{
    static const char case_name[] = "decrypt trailing byte";
    zupt_keyring_t keyring;
    zupt_keyring_t keyring_before;
    uint8_t header[TEST_HEADER_CAPACITY];

    reset_provider();
    memset(&keyring, 0x83, sizeof(keyring));
    keyring_before = keyring;
    memset(header, 0, sizeof(header));
    write_declared_size(header, 8);
    memcpy(header + 5, provider_blob, 8);
    header[13] = 0xee;
    if (zupt_sdk_hybrid_decrypt_init(&keyring, "recipient.key", header, 14) == 0)
        fail(case_name, "accepted bytes after the declared SDK blob");
    if (decrypt_calls != 0)
        fail(case_name, "called the provider for a malformed envelope");
    if (memcmp(&keyring, &keyring_before, sizeof(keyring)) != 0)
        fail(case_name, "changed the keyring for a malformed envelope");
}

static void test_decrypt_rejects_zero_length_blob(void)
{
    static const char case_name[] = "decrypt zero-length provider blob";
    zupt_keyring_t keyring;
    zupt_keyring_t keyring_before;
    uint8_t header[5] = {0};

    reset_provider();
    memset(&keyring, 0x73, sizeof(keyring));
    keyring_before = keyring;
    write_declared_size(header, 0);
    if (zupt_sdk_hybrid_decrypt_init(&keyring, "recipient.key", header,
                                     sizeof(header)) == 0)
        fail(case_name, "accepted an empty provider blob");
    if (decrypt_calls != 0)
        fail(case_name, "called the provider for an empty blob");
    if (memcmp(&keyring, &keyring_before, sizeof(keyring)) != 0)
        fail(case_name, "changed the keyring for an empty blob");
}

static void test_decrypt_rejects_oversize(void)
{
    static const char case_name[] = "decrypt oversize envelope";
    zupt_keyring_t keyring;
    zupt_keyring_t keyring_before;
    uint8_t header[TEST_HEADER_CAPACITY + 1];

    reset_provider();
    memset(&keyring, 0x47, sizeof(keyring));
    keyring_before = keyring;
    memset(header, 0, sizeof(header));
    write_declared_size(header, TEST_BLOB_CAPACITY);
    if (zupt_sdk_hybrid_decrypt_init(&keyring, "recipient.key", header,
                                     sizeof(header)) == 0)
        fail(case_name, "accepted an envelope larger than 1500 bytes");
    if (decrypt_calls != 0)
        fail(case_name, "called the provider for an oversize envelope");
    if (memcmp(&keyring, &keyring_before, sizeof(keyring)) != 0)
        fail(case_name, "changed the keyring for an oversize envelope");
}

int main(void)
{
    test_encrypt_success();
    test_encrypt_maximum_blob();
    test_encrypt_provider_error_with_blob();
    test_encrypt_null_blob();
    test_encrypt_zero_length_blob();
    test_encrypt_oversize(TEST_BLOB_CAPACITY, "encrypt 1496-byte blob");
    test_encrypt_oversize(SIZE_MAX, "encrypt SIZE_MAX blob");
    test_decrypt_exact_envelope();
    test_decrypt_maximum_blob();
    test_decrypt_provider_error_with_plaintext();
    test_decrypt_wrong_plaintext_size();
    test_decrypt_rejects_trailing_byte();
    test_decrypt_rejects_zero_length_blob();
    test_decrypt_rejects_oversize();

    if (failures != 0) {
        fprintf(stderr, "SDK adapter boundary tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("PASS: SDK adapter validates exact envelopes and provider ownership");
    return 0;
}
