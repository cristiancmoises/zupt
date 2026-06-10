/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 *
 * Incremental HMAC-SHA256 equivalence test (v3.3.0).
 *
 * The per-block Encrypt-then-MAC hot path was changed from
 *   one-shot HMAC over a malloc'd (aad || nonce || ciphertext || seq)
 *   concat buffer
 * to
 *   incremental HMAC streamed segment-by-segment (no concat, no copy).
 *
 * RFC 2104 + SHA-256's Merkle-Damgard update() guarantee these produce
 * identical tags, but that guarantee is load-bearing for wire-format
 * compatibility (old archives must still authenticate). This test pins
 * it down:
 *   1. zupt_hmac_sha256 one-shot == manual init/update/final, single seg.
 *   2. Streaming the message in arbitrary chunk splits == one-shot over
 *      the whole message, across many lengths and split points.
 *   3. The exact per-block segment pattern used by the codec
 *      (aad_extra || nonce || ciphertext || aad_seq) streamed in 4
 *      updates == one-shot over the concatenation. This is the precise
 *      invariant the encrypt/decrypt paths rely on.
 *   4. RFC 4231 Test Case 2 known-answer (sanity that the base HMAC is
 *      still correct after the refactor).
 */
#include "zupt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int pass = 0, fail = 0;
static void ok(const char *m)  { printf("  \xE2\x9C\x93 %s\n", m); pass++; }
static void bad(const char *m) { printf("  \xE2\x9C\x97 %s\n", m); fail++; }

static int eq32(const uint8_t a[32], const uint8_t b[32]) {
    return memcmp(a, b, 32) == 0;
}

int main(void) {
    printf("Incremental HMAC-SHA256 equivalence\n");

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);

    /* 1. one-shot == manual init/update/final (single segment) */
    {
        const uint8_t msg[] = "the quick brown fox";
        uint8_t a[32], b[32];
        zupt_hmac_sha256(key, 32, msg, sizeof(msg) - 1, a);
        zupt_hmac_ctx c;
        zupt_hmac_sha256_init(&c, key, 32);
        zupt_hmac_sha256_update(&c, msg, sizeof(msg) - 1);
        zupt_hmac_sha256_final(&c, b);
        if (eq32(a, b)) ok("one-shot == init/update/final (single segment)");
        else bad("one-shot != incremental (single segment)");
    }

    /* 2. arbitrary chunk splits == one-shot, many lengths */
    {
        size_t lens[] = {0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 1000, 4096, 100000};
        int all_ok = 1;
        uint8_t *buf = (uint8_t *)malloc(100000);
        for (size_t i = 0; i < 100000; i++) buf[i] = (uint8_t)(i * 131 + 17);
        for (size_t li = 0; li < sizeof(lens)/sizeof(lens[0]); li++) {
            size_t n = lens[li];
            uint8_t ref[32];
            zupt_hmac_sha256(key, 32, buf, n, ref);
            /* split into 1, 2, and 3 pieces at varied points */
            for (int parts = 1; parts <= 3; parts++) {
                uint8_t got[32];
                zupt_hmac_ctx c;
                zupt_hmac_sha256_init(&c, key, 32);
                size_t off = 0;
                for (int p = 0; p < parts; p++) {
                    size_t remain = n - off;
                    size_t chunk = (p == parts - 1) ? remain : remain / (size_t)(parts - p);
                    zupt_hmac_sha256_update(&c, buf + off, chunk);
                    off += chunk;
                }
                zupt_hmac_sha256_final(&c, got);
                if (!eq32(ref, got)) { all_ok = 0; }
            }
        }
        free(buf);
        if (all_ok) ok("streamed splits (1/2/3 parts) == one-shot, lengths 0..100000");
        else bad("streamed split != one-shot for some length/split");
    }

    /* 3. exact per-block segment pattern: aad || nonce || ct || seq */
    {
        uint8_t aad[29], nonce[16], seq[8];
        uint8_t ct[5000];
        for (int i = 0; i < 29; i++) aad[i] = (uint8_t)(i + 100);
        for (int i = 0; i < 16; i++) nonce[i] = (uint8_t)(i * 3);
        for (int i = 0; i < 8; i++) seq[i] = (uint8_t)(i + 200);
        for (int i = 0; i < 5000; i++) ct[i] = (uint8_t)(i * 53 + 9);

        /* one-shot over the concatenation (the OLD method) */
        size_t total = 29 + 16 + 5000 + 8;
        uint8_t *concat = (uint8_t *)malloc(total);
        size_t o = 0;
        memcpy(concat + o, aad, 29);   o += 29;
        memcpy(concat + o, nonce, 16); o += 16;
        memcpy(concat + o, ct, 5000);  o += 5000;
        memcpy(concat + o, seq, 8);    o += 8;
        uint8_t ref[32];
        zupt_hmac_sha256(key, 32, concat, total, ref);
        free(concat);

        /* streamed (the NEW method) */
        uint8_t got[32];
        zupt_hmac_ctx c;
        zupt_hmac_sha256_init(&c, key, 32);
        zupt_hmac_sha256_update(&c, aad, 29);
        zupt_hmac_sha256_update(&c, nonce, 16);
        zupt_hmac_sha256_update(&c, ct, 5000);
        zupt_hmac_sha256_update(&c, seq, 8);
        zupt_hmac_sha256_final(&c, got);

        if (eq32(ref, got)) ok("per-block pattern (aad||nonce||ct||seq) streamed == concat one-shot");
        else bad("per-block streamed pattern != concat one-shot");
    }

    /* 4. RFC 4231 Test Case 2 known-answer */
    {
        /* Key = "Jefe", Data = "what do ya want for nothing?" */
        const uint8_t k[] = "Jefe";
        const uint8_t d[] = "what do ya want for nothing?";
        uint8_t mac[32];
        zupt_hmac_sha256(k, 4, d, 28, mac);
        char hx[65];
        for (int i = 0; i < 32; i++) sprintf(hx + i*2, "%02x", mac[i]);
        if (strcmp(hx, "5bdcc146bf60754e6a042426089575c7"
                       "5a003f089d2739839dec58b964ec3843") == 0)
            ok("RFC 4231 TC2 known-answer correct");
        else { bad("RFC 4231 TC2 WRONG"); printf("    got %s\n", hx); }
    }

    printf("\n  ───────────────────────────────────────\n");
    printf("  Incremental HMAC: %d passed, %d failed\n", pass, fail);
    printf("  ───────────────────────────────────────\n");
    return fail ? 1 : 0;
}
