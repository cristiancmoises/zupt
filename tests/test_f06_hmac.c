/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 *
 * F-06 regression test (Zupt 2.2.5).
 *
 * The original combined-diff in zupt_decrypt_buffer was
 *     uint64_t diff = diff_v2 & diff_v1;
 * which on the Jasmin path (full 64-bit OR-of-4-chunks accumulators) accepts
 * single-bit MAC tampers with probability ≈ 4/64 ≈ 6% — wherever the bit
 * flipped in diff_v2 happens to fall on one of the rare zero bits of diff_v1.
 *
 * This test produces N independent encrypt(plaintext) packages with fresh
 * keys, flips one bit of the stored MAC in each, and asserts every single
 * tampered package is rejected on decrypt. With N=2000 the bug, if present,
 * would surface ~120 acceptances; we accept zero. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zupt.h"

extern uint8_t *zupt_encrypt_buffer(const zupt_keyring_t *kr,
                                    const uint8_t *plain, size_t plen,
                                    uint64_t block_seq, size_t *olen);
extern uint8_t *zupt_decrypt_buffer(const zupt_keyring_t *kr,
                                    const uint8_t *pkg, size_t pkglen,
                                    uint64_t block_seq, size_t *olen);
extern void zupt_random_bytes(uint8_t *buf, size_t len);

static int run_trial(uint64_t seed_offset) {
    zupt_keyring_t kr;
    zupt_keyring_init(&kr);
    zupt_random_bytes(kr.enc_key, sizeof(kr.enc_key));
    zupt_random_bytes(kr.mac_key, sizeof(kr.mac_key));
    zupt_random_bytes(kr.base_nonce, sizeof(kr.base_nonce));
    kr.active = 1;

    /* Plaintext: short and not all-zero, so the ciphertext doesn't accidentally
     * leak structural cues if the test ever inspects it. */
    const char *plain = "F-06 regression plaintext payload — block_seq matters";
    size_t plen = strlen(plain);

    size_t pkg_len = 0;
    uint8_t *pkg = zupt_encrypt_buffer(&kr, (const uint8_t *)plain, plen,
                                       0x0123456789ABCDEFULL + seed_offset, &pkg_len);
    if (!pkg) return -1;

    /* Sanity: untouched package decrypts. */
    {
        size_t dlen = 0;
        uint8_t *dec = zupt_decrypt_buffer(&kr, pkg, pkg_len,
                                           0x0123456789ABCDEFULL + seed_offset, &dlen);
        if (!dec || dlen != plen || memcmp(dec, plain, plen) != 0) {
            free(dec); free(pkg);
            return -2; /* honest roundtrip broken — separate bug */
        }
        zupt_secure_wipe(dec, dlen);
        free(dec);
    }

    /* F-06 probe: flip one bit of the stored MAC (last 32 bytes of pkg).
     * The bit chosen rotates across trials to exercise the full HMAC
     * surface, not just one position. */
    size_t mac_off = pkg_len - ZUPT_HMAC_SIZE;
    size_t bit_pos = seed_offset & 0xFF;            /* 0..255 → bit within HMAC */
    size_t byte_within_mac = bit_pos >> 3;          /* 0..31 */
    uint8_t bit_mask = (uint8_t)(1u << (bit_pos & 7));
    pkg[mac_off + byte_within_mac] ^= bit_mask;

    /* Expectation: decrypt MUST return NULL (auth fail). */
    size_t dlen = 0;
    uint8_t *dec = zupt_decrypt_buffer(&kr, pkg, pkg_len,
                                       0x0123456789ABCDEFULL + seed_offset, &dlen);
    int silent_accept = (dec != NULL);
    if (dec) {
        zupt_secure_wipe(dec, dlen);
        free(dec);
    }
    free(pkg);
    return silent_accept;
}

int main(void) {
    const int N = 2000;
    int accepted = 0;
    int sanity_fails = 0;
    int roundtrip_fails = 0;

    fputs("F-06 regression: 2000 trials, 1-bit HMAC tamper each\n", stderr);

    for (int i = 0; i < N; i++) {
        int r = run_trial((uint64_t)i);
        if (r == 1) accepted++;
        else if (r == -1) sanity_fails++;
        else if (r == -2) roundtrip_fails++;
    }

    fprintf(stderr, "  honest roundtrips OK:    %d/%d\n", N - sanity_fails - roundtrip_fails, N);
    fprintf(stderr, "  encrypt-buffer failures: %d (must be 0)\n", sanity_fails);
    fprintf(stderr, "  roundtrip mismatches:    %d (must be 0)\n", roundtrip_fails);
    fprintf(stderr, "  silent-accepted tampers: %d (must be 0)\n", accepted);

    if (sanity_fails || roundtrip_fails || accepted) {
        fprintf(stderr, "F-06 regression: FAIL\n");
        return 1;
    }
    fprintf(stderr, "F-06 regression: PASS\n");
    return 0;
}
