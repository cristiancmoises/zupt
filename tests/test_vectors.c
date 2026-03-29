/*
 * Zupt — NIST/RFC Cryptographic Test Vectors
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Tests: SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 4231),
 *        X25519 (RFC 7748 §6.1), ML-KEM-768 roundtrip,
 *        SHA3-256 (FIPS 202), SHAKE-128 (FIPS 202).
 *
 * Build: gcc -O2 -std=c11 -Iinclude -Isrc tests/test_vectors.c \
 *        src/zupt_sha256.c src/zupt_crypto.c src/zupt_aes256.c \
 *        src/zupt_xxh.c src/zupt_keccak.c src/zupt_x25519.c \
 *        src/zupt_mlkem.c -lm -o test_vectors
 */
#define _GNU_SOURCE
#include "zupt.h"
#include "zupt_keccak.h"
#include "zupt_x25519.h"
#include "zupt_mlkem.h"
#include <stdio.h>
#include <string.h>

static int pass = 0, fail = 0;
static void check(const char *name, const uint8_t *got, const uint8_t *exp, int n) {
    if (memcmp(got, exp, (size_t)n) == 0) { printf("  OK:   %s\n", name); pass++; }
    else {
        printf("  FAIL: %s\n    got: ", name);
        for (int i = 0; i < (n < 16 ? n : 16); i++) printf("%02x", got[i]);
        printf("...\n    exp: ");
        for (int i = 0; i < (n < 16 ? n : 16); i++) printf("%02x", exp[i]);
        printf("...\n");
        fail++;
    }
}

static void hex2bin(const char *hex, uint8_t *bin, int len) {
    for (int i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + 2*i, "%02x", &b);
        bin[i] = (uint8_t)b;
    }
}

int main(void) {
    printf("Zupt Cryptographic Test Vectors\n");
    printf("================================\n\n");

    /* ═══ SHA-256 (FIPS 180-4) ═══ */
    printf("-- SHA-256 (FIPS 180-4) --\n");
    {
        /* Test 1: "abc" → ba7816bf... */
        uint8_t h[32];
        zupt_sha256((const uint8_t *)"abc", 3, h);
        uint8_t exp[32];
        hex2bin("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", exp, 32);
        check("SHA-256('abc')", h, exp, 32);

        /* Test 2: "" (empty) → e3b0c442... */
        zupt_sha256((const uint8_t *)"", 0, h);
        hex2bin("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", exp, 32);
        check("SHA-256('')", h, exp, 32);

        /* Test 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
        const char *msg3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        zupt_sha256((const uint8_t *)msg3, strlen(msg3), h);
        hex2bin("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", exp, 32);
        check("SHA-256(448-bit)", h, exp, 32);
    }

    /* ═══ HMAC-SHA256 (RFC 4231) ═══ */
    printf("\n-- HMAC-SHA256 (RFC 4231) --\n");
    {
        /* Test Case 2: key=4a656665("Jefe"), data="what do ya want for nothing?" */
        uint8_t mac[32], exp[32];
        zupt_hmac_sha256((const uint8_t *)"Jefe", 4,
                         (const uint8_t *)"what do ya want for nothing?", 28, mac);
        hex2bin("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", exp, 32);
        check("HMAC-SHA256(RFC4231 TC2)", mac, exp, 32);

        /* Test Case 3: key=20*0xaa, data=50*0xdd */
        uint8_t key3[20], data3[50];
        memset(key3, 0xaa, 20);
        memset(data3, 0xdd, 50);
        zupt_hmac_sha256(key3, 20, data3, 50, mac);
        hex2bin("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", exp, 32);
        check("HMAC-SHA256(RFC4231 TC3)", mac, exp, 32);
    }

    /* ═══ SHA3-256 (FIPS 202) ═══ */
    printf("\n-- SHA3-256 (FIPS 202) --\n");
    {
        uint8_t h[32], exp[32];

        /* Empty message */
        zupt_sha3_256((const uint8_t *)"", 0, h);
        hex2bin("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", exp, 32);
        check("SHA3-256('')", h, exp, 32);

        /* "abc" */
        zupt_sha3_256((const uint8_t *)"abc", 3, h);
        hex2bin("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", exp, 32);
        check("SHA3-256('abc')", h, exp, 32);
    }

    /* ═══ SHAKE-128 (FIPS 202) ═══ */
    printf("\n-- SHAKE-128 (FIPS 202) --\n");
    {
        uint8_t out[16], exp[16];
        /* Empty input, 128-bit output */
        zupt_shake128((const uint8_t *)"", 0, out, 16);
        hex2bin("7f9c2ba4e88f827d616045507605853e", exp, 16);
        check("SHAKE-128('', 16B)", out, exp, 16);
    }

    /* ═══ X25519 (RFC 7748 §6.1) ═══ */
    printf("\n-- X25519 (RFC 7748 §6.1) --\n");
    {
        uint8_t scalar[32], u[32], result[32], exp[32];

        /* Test vector 1 */
        hex2bin("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar, 32);
        hex2bin("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32);
        zupt_x25519(result, scalar, u);
        hex2bin("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", exp, 32);
        check("X25519 TV1", result, exp, 32);

        /* Test vector 2 */
        hex2bin("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", scalar, 32);
        hex2bin("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u, 32);
        zupt_x25519(result, scalar, u);
        hex2bin("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", exp, 32);
        check("X25519 TV2", result, exp, 32);
    }

    /* ═══ ML-KEM-768 (roundtrip) ═══ */
    printf("\n-- ML-KEM-768 (FIPS 203 roundtrip) --\n");
    {
        uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
        int kem_ok = 1;
        for (int trial = 0; trial < 5; trial++) {
            zupt_mlkem768_keygen(pk, sk);
            zupt_mlkem768_encaps(ct, ss1, pk);
            zupt_mlkem768_decaps(ss2, ct, sk);
            if (memcmp(ss1, ss2, 32) != 0) { kem_ok = 0; break; }
        }
        if (kem_ok) { printf("  OK:   ML-KEM-768 roundtrip (5 trials)\n"); pass++; }
        else { printf("  FAIL: ML-KEM-768 roundtrip\n"); fail++; }

        /* Implicit rejection: corrupt ct, verify different ss */
        zupt_mlkem768_keygen(pk, sk);
        zupt_mlkem768_encaps(ct, ss1, pk);
        ct[0] ^= 0xFF; /* Corrupt first byte */
        zupt_mlkem768_decaps(ss2, ct, sk);
        if (memcmp(ss1, ss2, 32) != 0) {
            printf("  OK:   ML-KEM-768 implicit rejection\n"); pass++;
        } else {
            printf("  FAIL: ML-KEM-768 implicit rejection (ss should differ)\n"); fail++;
        }
    }

    /* ═══ XXH64 (basic sanity) ═══ */
    printf("\n-- XXH64 --\n");
    {
        uint64_t h = zupt_xxh64((const uint8_t *)"", 0, 0);
        /* xxh64("", seed=0) = 0xef46db3751d8e999 */
        if (h == UINT64_C(0xef46db3751d8e999)) { printf("  OK:   XXH64('')\n"); pass++; }
        else { printf("  FAIL: XXH64('') = %016llx\n", (unsigned long long)h); fail++; }
    }

    printf("\n================================\n");
    printf("Results: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
