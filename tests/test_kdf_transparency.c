/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 *
 * F-15 — Argon2id KDF parameter transparency (v3.4.0).
 *
 * The 0x04 Argon2id enc-header historically recorded only
 * [type|salt|nonce] and nothing about the KDF cost, unlike the PBKDF2
 * header which records its iteration count. A non-self-describing KDF
 * header is a latent robustness/security problem for an archive format
 * meant to last years: if the Argon2id cost preset ever changed, old
 * archives could silently become undecryptable.
 *
 * v3.4.0 appends a one-byte KDF profile descriptor at offset 33. This
 * test pins:
 *   1. A newly written Argon2id header is 34 bytes and carries the
 *      MODERATE profile (0x01).
 *   2. decrypt-init accepts a legacy 33-byte header (profile implicit)
 *      and an explicit 34-byte MODERATE header, and derives the SAME
 *      keys for both (so old archives keep opening).
 *   3. decrypt-init REFUSES an unknown profile rather than guessing a
 *      derivation (fail-closed).
 *   4. The underlying libzuptsdk Argon2id KDF is deterministic and
 *      memory-hard (a coarse cost floor) — this catches an SDK that has
 *      been swapped for a fast/weak stand-in at build time, before a
 *      user discovers their backup won't open or is under-protected.
 */
#include "zupt.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* easy-derive is the only KDF symbol the vendored SDK exports. */
int zuptsdk_easy_derive_key(const char *password, const uint8_t salt[16], uint8_t key_out[32]);
int zupt_sdk_password_encrypt_init(zupt_keyring_t *kr, const char *password,
                                   uint8_t *enc_hdr, size_t *enc_hdr_len);
int zupt_sdk_password_decrypt_init(zupt_keyring_t *kr, const char *password,
                                   const uint8_t *enc_hdr, size_t enc_hdr_len);

static int pass = 0, fail = 0;
static void ok(const char *m)  { printf("  \xE2\x9C\x93 %s\n", m); pass++; }
static void bad(const char *m) { printf("  \xE2\x9C\x97 %s\n", m); fail++; }

int main(void) {
    printf("F-15 Argon2id KDF transparency\n");

    /* 1. New header shape */
    zupt_keyring_t kr; memset(&kr, 0, sizeof kr);
    uint8_t hdr[64]; size_t hlen = 0;
    if (zupt_sdk_password_encrypt_init(&kr, "correct horse", hdr, &hlen) != 0) {
        bad("encrypt-init failed"); printf("  F-15: %d/%d\n", pass, fail); return 1;
    }
    if (hlen == ZUPT_ARGON2_HDR_LEN_V2 &&
        hdr[0] == ZUPT_ENC_PW_ARGON2 &&
        hdr[33] == ZUPT_ARGON2_PROFILE_MODERATE)
        ok("new Argon2id header is 34 bytes with explicit MODERATE profile");
    else
        bad("new Argon2id header missing/incorrect profile descriptor");

    /* 2. Legacy 33B and explicit 34B derive identical keys. */
    {
        /* Build a fixed header (known salt) both ways. */
        uint8_t base[34]; memset(base, 0, sizeof base);
        base[0] = ZUPT_ENC_PW_ARGON2;
        for (int i = 0; i < 16; i++) base[1 + i] = (uint8_t)(i + 1);   /* salt */
        for (int i = 0; i < 16; i++) base[17 + i] = (uint8_t)(i + 100); /* nonce */
        base[33] = ZUPT_ARGON2_PROFILE_MODERATE;

        zupt_keyring_t k33; memset(&k33, 0, sizeof k33);
        zupt_keyring_t k34; memset(&k34, 0, sizeof k34);
        int r33 = zupt_sdk_password_decrypt_init(&k33, "pw", base, ZUPT_ARGON2_HDR_LEN_V1);
        int r34 = zupt_sdk_password_decrypt_init(&k34, "pw", base, ZUPT_ARGON2_HDR_LEN_V2);
        if (r33 == 0 && r34 == 0 &&
            memcmp(k33.enc_key, k34.enc_key, 32) == 0 &&
            memcmp(k33.mac_key, k34.mac_key, 32) == 0)
            ok("legacy 33B and explicit 34B headers derive identical keys");
        else
            bad("33B vs 34B header key mismatch (back-compat broken)");
    }

    /* 3. Unknown profile is refused (fail-closed). */
    {
        uint8_t bad_hdr[34]; memset(bad_hdr, 0, sizeof bad_hdr);
        bad_hdr[0] = ZUPT_ENC_PW_ARGON2;
        bad_hdr[33] = 0x99; /* not a known profile */
        zupt_keyring_t kx; memset(&kx, 0, sizeof kx);
        int r = zupt_sdk_password_decrypt_init(&kx, "pw", bad_hdr, ZUPT_ARGON2_HDR_LEN_V2);
        if (r != 0) ok("unknown KDF profile is refused (fail-closed, no wrong-key guess)");
        else bad("unknown KDF profile was accepted");
    }

    /* 4. KDF is deterministic and memory-hard (coarse cost floor). */
    {
        uint8_t salt[16]; memset(salt, 7, 16);
        uint8_t k1[32], k2[32];
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        int r1 = zuptsdk_easy_derive_key("benchmark-pw", salt, k1);
        clock_gettime(CLOCK_MONOTONIC, &b);
        int r2 = zuptsdk_easy_derive_key("benchmark-pw", salt, k2);
        double ms = (double)(b.tv_sec - a.tv_sec) * 1000.0
                  + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
        if (r1 == 0 && r2 == 0 && memcmp(k1, k2, 32) == 0)
            ok("Argon2id KDF is deterministic (same password+salt -> same key)");
        else
            bad("Argon2id KDF not deterministic");
        /* Memory-hard Argon2id at the MODERATE preset takes hundreds of ms
         * on current hardware. A sub-20ms derivation almost certainly means
         * the SDK was replaced with a non-memory-hard stand-in — refuse to
         * pass so the regression is caught at build time, not by a user. */
        if (ms >= 20.0)
            ok("Argon2id KDF cost floor met (memory-hard preset active)");
        else {
            char buf[96];
            snprintf(buf, sizeof buf, "Argon2id KDF suspiciously fast (%.1f ms) — weak/stub SDK?", ms);
            bad(buf);
        }
    }

    printf("\n  ───────────────────────────────────────\n");
    printf("  F-15 KDF transparency: %d passed, %d failed\n", pass, fail);
    printf("  ───────────────────────────────────────\n");
    return fail ? 1 : 0;
}
