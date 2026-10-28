/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * AES4 functional checks against NIST SP 800-38A F.5.5 and OpenSSL ECB.
 * The Zupt counter increments only its low, big-endian 64-bit word.
 */
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void zupt_aes256_ctr4(void *out, const void *in, const void *key,
                           void *counter, uint64_t blocks);

enum { MAX_BLOCKS = 64, MAX_BYTES = 16 * MAX_BLOCKS, STORAGE = MAX_BYTES + 64 };
static uint32_t fixture_state = UINT32_C(0x43545234);

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

static void increment_counter(uint8_t counter[16])
{
    for (size_t i = 16; i > 8; --i)
        if (++counter[i - 1] != 0) break;
}

/* EVP's CTR cipher carries through 128 bits. Use ECB plus the documented
 * low-word increment so wraparound does not silently change the oracle. */
static int oracle(const uint8_t key[32], const uint8_t counter[16],
                  const uint8_t *input, size_t blocks, uint8_t *expected,
                  uint8_t final_counter[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t stream[32];
    int produced = 0, tail = 0;
    int ok = ctx != NULL &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1;
    memcpy(final_counter, counter, 16);
    for (size_t i = 0; ok && i < blocks; ++i) {
        ok = EVP_EncryptUpdate(ctx, stream, &produced, final_counter, 16) == 1 &&
            produced == 16;
        if (ok) {
            for (size_t j = 0; j < 16; ++j)
                expected[16 * i + j] = stream[j] ^ input[16 * i + j];
            increment_counter(final_counter);
        }
    }
    if (ok) ok = EVP_EncryptFinal_ex(ctx, stream, &tail) == 1 && tail == 0;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int padding_intact(const uint8_t *buf, size_t size,
                          size_t offset, size_t length)
{
    for (size_t i = 0; i < size; ++i)
        if ((i < offset || i >= offset + length) && buf[i] != UINT8_C(0xa5))
            return 0;
    return 1;
}

/* Canaries check writes outside valid slices, not assembly read bounds. */
static int run_case(const uint8_t key[32], const uint8_t counter[16],
                    const uint8_t *input, const uint8_t *expected,
                    const uint8_t final_counter[16], size_t blocks,
                    unsigned index, int inplace, size_t split)
{
    uint8_t key_mem[80], counter_mem[80], input_mem[STORAGE], output_mem[STORAGE];
    size_t ko = 16 + (index & 15u), co = 16 + ((index >> 2) & 15u);
    size_t io = 16 + ((index >> 4) & 15u), oo = 16 + ((index >> 1) & 15u);
    size_t bytes = blocks * 16;
    memset(key_mem, 0xa5, sizeof(key_mem));
    memset(counter_mem, 0xa5, sizeof(counter_mem));
    memset(input_mem, 0xa5, sizeof(input_mem));
    memset(output_mem, 0xa5, sizeof(output_mem));
    memcpy(key_mem + ko, key, 32);
    memcpy(counter_mem + co, counter, 16);
    memcpy(input_mem + io, input, bytes);
    uint8_t *out = inplace ? input_mem + io : output_mem + oo;
    if (split > 0 && split < blocks) {
        zupt_aes256_ctr4(out, input_mem + io, key_mem + ko, counter_mem + co,
                        (uint64_t)split);
        zupt_aes256_ctr4(out + split * 16, input_mem + io + split * 16,
                        key_mem + ko, counter_mem + co, (uint64_t)(blocks - split));
    } else {
        zupt_aes256_ctr4(out, input_mem + io, key_mem + ko, counter_mem + co,
                        (uint64_t)blocks);
    }
    int ok = memcmp(out, expected, bytes) == 0 &&
        memcmp(counter_mem + co, final_counter, 16) == 0 &&
        memcmp(key_mem + ko, key, 32) == 0 &&
        (inplace || memcmp(input_mem + io, input, bytes) == 0) &&
        padding_intact(key_mem, sizeof(key_mem), ko, 32) &&
        padding_intact(counter_mem, sizeof(counter_mem), co, 16) &&
        padding_intact(input_mem, sizeof(input_mem), io, bytes) &&
        padding_intact(output_mem, sizeof(output_mem), oo, bytes);
    if (!ok)
        fprintf(stderr, "FAIL: AES4 case=%u blocks=%zu inplace=%d split=%zu\n",
                index, blocks, inplace, split);
    return ok;
}

int main(void)
{
    __builtin_cpu_init();
    if (!__builtin_cpu_supports("aes") || !__builtin_cpu_supports("avx")) {
        fputs("BLOCKED: AES-NI and OS-enabled AVX required\n", stderr);
        return 77;
    }
    uint8_t key[32], counter[16], input[MAX_BYTES], expected[MAX_BYTES];
    uint8_t final_counter[16], nist[64];
    unsigned failures = 0;
    if (!decode_hex("603deb1015ca71be2b73aef0857d7781"
                    "1f352c073b6108d72d9810a30914dff4", key, 32) ||
        !decode_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", counter, 16) ||
        !decode_hex("6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710", input, 64) ||
        !decode_hex("601ec313775789a5b7a7f504bbf3d228"
                    "f443e3ca4d62b59aca84e990cacaf5c5"
                    "2b0930daa23de94ce87017ba2d84988d"
                    "dfc9c58db67aada613c2dd08457941a6", nist, 64))
        return 2;
    if (!oracle(key, counter, input, 4, expected, final_counter) ||
        memcmp(expected, nist, sizeof(nist)) != 0) {
        fputs("FAIL: OpenSSL oracle disagrees with NIST CTR vector\n", stderr);
        return 2;
    }
    failures += (unsigned)!run_case(key, counter, input, expected,
                                    final_counter, 4, 0, 0, 0);
    for (int inplace = 0; inplace < 2; ++inplace) {
        unsigned group_failures = 0;
        for (unsigned i = 0; i < 512; ++i) {
            size_t blocks = 1 + (i % MAX_BLOCKS);
            fill_fixture(key, sizeof(key));
            fill_fixture(counter, sizeof(counter));
            fill_fixture(input, blocks * 16);
            if ((i & 7u) == 0) {
                memset(counter + 8, 0xff, 8);
                counter[15] -= (uint8_t)((i >> 3) & 31u);
            }
            if (!oracle(key, counter, input, blocks, expected, final_counter))
                return 2;
            group_failures += (unsigned)!run_case(key, counter, input, expected,
                                        final_counter, blocks, i, inplace, 0);
        }
        printf("%s: AES4 differential %s cases=512 failures=%u\n",
               group_failures ? "FAIL" : "PASS", inplace ? "in-place" : "separate",
               group_failures);
        failures += group_failures;
    }
    for (int inplace = 0; inplace < 2; ++inplace) {
        unsigned group_failures = 0;
        for (unsigned i = 0; i < 256; ++i) {
            size_t blocks = 2 + (i % (MAX_BLOCKS - 1));
            size_t split = 1 + (i % (blocks - 1));
            fill_fixture(key, sizeof(key));
            fill_fixture(counter, sizeof(counter));
            fill_fixture(input, blocks * 16);
            memset(counter + 8, 0xff, 8);
            counter[15] = (uint8_t)(255u - (unsigned)split);
            if (!oracle(key, counter, input, blocks, expected, final_counter))
                return 2;
            group_failures += (unsigned)!run_case(key, counter, input, expected,
                                    final_counter, blocks, i, inplace, split);
        }
        /* Exercise the generated routine's zero-count no-touch contract only.
         * All arguments here point into live, canary-protected buffers. */
        memcpy(final_counter, counter, 16);
        group_failures += (unsigned)!run_case(key, counter, input, expected,
                                        final_counter, 0, 15, inplace, 0);
        printf("%s: AES4 split-call/zero-count %s cases=257 failures=%u\n",
               group_failures ? "FAIL" : "PASS", inplace ? "in-place" : "separate",
               group_failures);
        failures += group_failures;
    }
    printf("Summary: failures=%u total_cases=1539 seed=0x43545234\n", failures);
    return failures ? 1 : 0;
}
