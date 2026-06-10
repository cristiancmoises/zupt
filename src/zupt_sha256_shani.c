/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 * ZUPT — SHA-256 hardware path (Intel SHA-NI)
 *
 * Implements the FIPS 180-4 SHA-256 compression function using the
 * Intel SHA Extensions (SHA-NI: SHA256RNDS2, SHA256MSG1, SHA256MSG2).
 * This is the same compression function as the scalar path in
 * zupt_sha256.c — bit-identical output — but 3-8x faster on CPUs that
 * implement the extensions (Intel Goldmont+/Ice Lake+, AMD Zen+).
 *
 * Security note: SHA-NI is constant-time by construction. It performs
 * no data-dependent memory accesses or branches, so it has a strictly
 * stronger side-channel posture than any table- or branch-based
 * software SHA-256. Since Zupt's authentication is HMAC-SHA256 over
 * attacker-influenced ciphertext, a constant-time compression function
 * is the right default wherever the hardware provides it.
 *
 * Dispatch: sha256_transform() in zupt_sha256.c calls
 * zupt_sha256_transform_shani() when zupt_cpu.has_shani is set. On
 * non-x86_64 targets this file compiles to nothing (the symbol is
 * never referenced because has_shani is always 0).
 *
 * Reference: Intel SHA Extensions whitepaper (Gulley, Gopal, Yap,
 * Feghali, Guilford, Wolrich, 2013) and the public-domain intrinsic
 * reference by Jeffrey Walton. This implementation was written against
 * the FIPS 180-4 spec and validated bit-exact against the scalar path
 * and the NIST FIPS 180-4 test vectors on both paths.
 */

#include "zupt.h"
#include "zupt_cpuid.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

#include <immintrin.h>
#include <stdint.h>
#include <string.h>

/* Process `blocks` 64-byte message blocks starting at `data`, updating
 * the eight 32-bit state words in `state` in place. Big-endian message
 * words per FIPS 180-4. */
void zupt_sha256_transform_shani(uint32_t state[8],
                                 const uint8_t *data, size_t blocks)
{
    __m128i STATE0, STATE1;
    __m128i MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    /* Byte-swap mask: SHA-NI consumes big-endian message words, but
     * _mm_loadu_si128 reads little-endian, so each 32-bit lane is
     * reversed with pshufb (SSSE3). */
    const __m128i MASK = _mm_set_epi64x(
        (long long)0x0c0d0e0f08090a0bULL,
        (long long)0x0405060700010203ULL);

    /* Load initial state. The SHA-NI register layout interleaves the
     * eight state words as two 128-bit halves:
     *   STATE0 = { C, D, G, H }  (after the shuffles below)
     *   STATE1 = { A, B, E, F }
     * We start from the natural {A,B,C,D} / {E,F,G,H} order and permute
     * into the SHA-NI ABEF/CDGH arrangement. */
    TMP    = _mm_loadu_si128((const __m128i *)&state[0]); /* A B C D */
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]); /* E F G H */

    TMP    = _mm_shuffle_epi32(TMP, 0xB1);          /* C D A B */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);       /* H G F E */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);       /* F E A B -> ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);    /* C D G H -> CDGH */

    while (blocks > 0) {
        /* Save current state for the feed-forward add at the end. */
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        /* Rounds 0-3 */
        MSG0 = _mm_loadu_si128((const __m128i *)(data + 0));
        MSG0 = _mm_shuffle_epi8(MSG0, MASK);
        MSG  = _mm_add_epi32(MSG0,
               _mm_set_epi64x((long long)0xE9B5DBA5B5C0FBCFULL,
                              (long long)0x71374491428A2F98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Rounds 4-7 */
        MSG1 = _mm_loadu_si128((const __m128i *)(data + 16));
        MSG1 = _mm_shuffle_epi8(MSG1, MASK);
        MSG  = _mm_add_epi32(MSG1,
               _mm_set_epi64x((long long)0xAB1C5ED5923F82A4ULL,
                              (long long)0x59F111F13956C25BULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* Rounds 8-11 */
        MSG2 = _mm_loadu_si128((const __m128i *)(data + 32));
        MSG2 = _mm_shuffle_epi8(MSG2, MASK);
        MSG  = _mm_add_epi32(MSG2,
               _mm_set_epi64x((long long)0x550C7DC3243185BEULL,
                              (long long)0x12835B01D807AA98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* Rounds 12-15 */
        MSG3 = _mm_loadu_si128((const __m128i *)(data + 48));
        MSG3 = _mm_shuffle_epi8(MSG3, MASK);
        MSG  = _mm_add_epi32(MSG3,
               _mm_set_epi64x((long long)0xC19BF1749BDC06A7ULL,
                              (long long)0x80DEB1FE72BE5D74ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0   = _mm_add_epi32(MSG0, TMP);
        MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* Rounds 16-19 */
        MSG  = _mm_add_epi32(MSG0,
               _mm_set_epi64x((long long)0x240CA1CC0FC19DC6ULL,
                              (long long)0xEFBE4786E49B69C1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1   = _mm_add_epi32(MSG1, TMP);
        MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* Rounds 20-23 */
        MSG  = _mm_add_epi32(MSG1,
               _mm_set_epi64x((long long)0x76F988DA5CB0A9DCULL,
                              (long long)0x4A7484AA2DE92C6FULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2   = _mm_add_epi32(MSG2, TMP);
        MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* Rounds 24-27 */
        MSG  = _mm_add_epi32(MSG2,
               _mm_set_epi64x((long long)0xBF597FC7B00327C8ULL,
                              (long long)0xA831C66D983E5152ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3   = _mm_add_epi32(MSG3, TMP);
        MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* Rounds 28-31 */
        MSG  = _mm_add_epi32(MSG3,
               _mm_set_epi64x((long long)0x1429296706CA6351ULL,
                              (long long)0xD5A79147C6E00BF3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0   = _mm_add_epi32(MSG0, TMP);
        MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* Rounds 32-35 */
        MSG  = _mm_add_epi32(MSG0,
               _mm_set_epi64x((long long)0x53380D134D2C6DFCULL,
                              (long long)0x2E1B213827B70A85ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1   = _mm_add_epi32(MSG1, TMP);
        MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* Rounds 36-39 */
        MSG  = _mm_add_epi32(MSG1,
               _mm_set_epi64x((long long)0x92722C8581C2C92EULL,
                              (long long)0x766A0ABB650A7354ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2   = _mm_add_epi32(MSG2, TMP);
        MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* Rounds 40-43 */
        MSG  = _mm_add_epi32(MSG2,
               _mm_set_epi64x((long long)0xC76C51A3C24B8B70ULL,
                              (long long)0xA81A664BA2BFE8A1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3   = _mm_add_epi32(MSG3, TMP);
        MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* Rounds 44-47 */
        MSG  = _mm_add_epi32(MSG3,
               _mm_set_epi64x((long long)0x106AA070F40E3585ULL,
                              (long long)0xD6990624D192E819ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0   = _mm_add_epi32(MSG0, TMP);
        MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* Rounds 48-51 */
        MSG  = _mm_add_epi32(MSG0,
               _mm_set_epi64x((long long)0x34B0BCB52748774CULL,
                              (long long)0x1E376C0819A4C116ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1   = _mm_add_epi32(MSG1, TMP);
        MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* Rounds 52-55 */
        MSG  = _mm_add_epi32(MSG1,
               _mm_set_epi64x((long long)0x682E6FF35B9CCA4FULL,
                              (long long)0x4ED8AA4A391C0CB3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2   = _mm_add_epi32(MSG2, TMP);
        MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Rounds 56-59 */
        MSG  = _mm_add_epi32(MSG2,
               _mm_set_epi64x((long long)0x8CC7020884C87814ULL,
                              (long long)0x78A5636F748F82EEULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3   = _mm_add_epi32(MSG3, TMP);
        MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Rounds 60-63 */
        MSG  = _mm_add_epi32(MSG3,
               _mm_set_epi64x((long long)0xC67178F2BEF9A3F7ULL,
                              (long long)0xA4506CEB90BEFFFAULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Feed-forward: add the saved state. */
        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

        data   += 64;
        blocks -= 1;
    }

    /* Permute the ABEF/CDGH halves back to the natural ABCD/EFGH order
     * and store. */
    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);       /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);    /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);       /* ABEF -> HGFE */

    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}

#else  /* non-x86: never referenced (has_shani is always 0) */

/* Translation unit must not be empty under -Wpedantic. */
typedef int zupt_sha256_shani_translation_unit_not_empty;

#endif
