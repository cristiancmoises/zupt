/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * AES single-block regression; NIST SP 800-38A F.1.5/F.5.5 and OpenSSL.
 */
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void zupt_aes256_blk(void *out, const void *in,
                           const void *key, const void *counter);

static unsigned failures;
static uint32_t fixture_state = UINT32_C(0x4a534d49);

static void fill_fixture(uint8_t *out, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        fixture_state ^= fixture_state << 13;
        fixture_state ^= fixture_state >> 17;
        fixture_state ^= fixture_state << 5;
        out[i] = (uint8_t)fixture_state;
    }
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int decode_hex(const char *hex, uint8_t *out, size_t size)
{
    if (strlen(hex) != size * 2) return 0;
    for (size_t i = 0; i < size; ++i) {
        int a = hex_nibble(hex[2 * i]);
        int b = hex_nibble(hex[2 * i + 1]);
        if (a < 0 || b < 0) return 0;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return 1;
}

static int oracle(const uint8_t key[32], const uint8_t counter[16],
                  const uint8_t input[16], uint8_t expected[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t stream[32];
    int produced = 0, tail = 0;
    int ok = ctx != NULL &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_EncryptUpdate(ctx, stream, &produced, counter, 16) == 1 &&
        produced == 16 &&
        EVP_EncryptFinal_ex(ctx, stream + produced, &tail) == 1 && tail == 0;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return 0;
    for (size_t i = 0; i < 16; ++i) expected[i] = stream[i] ^ input[i];
    return 1;
}

static int padding_intact(const uint8_t *buf, size_t size,
                          size_t offset, size_t length)
{
    for (size_t i = 0; i < size; ++i)
        if ((i < offset || i >= offset + length) && buf[i] != UINT8_C(0xa5))
            return 0;
    return 1;
}

/* Canaries detect writes outside the declared slices. They do not establish
 * read bounds or instrument the generated assembly. */
static int run_block(const uint8_t key[32], const uint8_t counter[16],
                     const uint8_t input[16], const uint8_t expected[16],
                     unsigned index, int inplace, unsigned *low_bad,
                     unsigned *upper_bad, unsigned *guard_bad)
{
    uint8_t key_mem[80], counter_mem[80], input_mem[80], output_mem[80];
    size_t ko = 16 + (index & 15u), co = 16 + ((index >> 2) & 15u);
    size_t io = 16 + ((index >> 4) & 15u), oo = 16 + ((index >> 1) & 15u);
    memset(key_mem, 0xa5, sizeof(key_mem));
    memset(counter_mem, 0xa5, sizeof(counter_mem));
    memset(input_mem, 0xa5, sizeof(input_mem));
    memset(output_mem, 0xa5, sizeof(output_mem));
    memcpy(key_mem + ko, key, 32);
    memcpy(counter_mem + co, counter, 16);
    memcpy(input_mem + io, input, 16);
    uint8_t *out = inplace ? input_mem + io : output_mem + oo;
    zupt_aes256_blk(out, input_mem + io, key_mem + ko, counter_mem + co);
    int low = memcmp(out, expected, 8) != 0;
    int upper = memcmp(out + 8, expected + 8, 8) != 0;
    int guards = !padding_intact(key_mem, sizeof(key_mem), ko, 32) ||
        !padding_intact(counter_mem, sizeof(counter_mem), co, 16) ||
        !padding_intact(input_mem, sizeof(input_mem), io, 16) ||
        !padding_intact(output_mem, sizeof(output_mem), oo, 16) ||
        memcmp(key_mem + ko, key, 32) != 0 ||
        memcmp(counter_mem + co, counter, 16) != 0 ||
        (!inplace && memcmp(input_mem + io, input, 16) != 0);
    *low_bad += (unsigned)low;
    *upper_bad += (unsigned)upper;
    *guard_bad += (unsigned)guards;
    return !low && !upper && !guards;
}

static void report(const char *label, unsigned cases, unsigned low,
                   unsigned upper, unsigned guards)
{
    int ok = low == 0 && upper == 0 && guards == 0;
    printf("%s: %s cases=%u low8_mismatch=%u upper8_mismatch=%u guards=%u\n",
           ok ? "PASS" : "FAIL", label, cases, low, upper, guards);
    if (!ok) ++failures;
}

int main(void)
{
    __builtin_cpu_init();
    if (!__builtin_cpu_supports("aes") || !__builtin_cpu_supports("avx")) {
        fputs("BLOCKED: AES-NI and OS-enabled AVX required\n", stderr);
        return 77;
    }
    uint8_t key[32], counter[16], input[16], expected[16], oracle_result[16];
    unsigned low = 0, upper = 0, guards = 0;
    if (!decode_hex("603deb1015ca71be2b73aef0857d7781"
                    "1f352c073b6108d72d9810a30914dff4", key, 32) ||
        !decode_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", counter, 16) ||
        !decode_hex("6bc1bee22e409f96e93d7e117393172a", input, 16) ||
        !decode_hex("601ec313775789a5b7a7f504bbf3d228", expected, 16))
        return 2;
    if (!oracle(key, counter, input, oracle_result) ||
        memcmp(oracle_result, expected, 16) != 0) {
        fputs("FAIL: OpenSSL oracle disagrees with NIST CTR vector\n", stderr);
        return 2;
    }
    (void)run_block(key, counter, input, expected, 0, 0, &low, &upper, &guards);
    report("NIST CTR-AES256 block 1", 1, low, upper, guards);

    memcpy(counter, input, 16);
    memset(input, 0, 16);
    if (!decode_hex("f3eed1bdb5d2a03c064b5a7e3db181f8", expected, 16) ||
        !oracle(key, counter, input, oracle_result) ||
        memcmp(oracle_result, expected, 16) != 0) return 2;
    low = upper = guards = 0;
    (void)run_block(key, counter, input, expected, 15, 0, &low, &upper, &guards);
    report("NIST ECB-AES256 block 1 with zero XOR input", 1, low, upper, guards);

    for (int inplace = 0; inplace < 2; ++inplace) {
        low = upper = guards = 0;
        for (unsigned i = 0; i < 512; ++i) {
            fill_fixture(key, sizeof(key));
            fill_fixture(counter, sizeof(counter));
            fill_fixture(input, sizeof(input));
            if (!oracle(key, counter, input, expected)) return 2;
            (void)run_block(key, counter, input, expected, i, inplace,
                            &low, &upper, &guards);
        }
        report(inplace ? "OpenSSL differential in-place/misaligned" :
                         "OpenSSL differential separate/misaligned",
               512, low, upper, guards);
    }
    printf("Summary: failed_groups=%u total_blocks=1026 seed=0x4a534d49\n", failures);
    return failures ? 1 : 0;
}
