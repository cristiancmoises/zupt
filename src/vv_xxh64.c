/*
 * SPDX-License-Identifier: GPL-3.0-or-later AND BSD-2-Clause
 * Copyright (c) 2012-2021 Yann Collet
 *
 * VaptVupt — XXH64 checksum (simplified, standalone)
 * Based on xxHash by Yann Collet. See LICENSE-BSD-2-Clause.
 */

#include "vaptvupt.h"
#include "vv_platform.h"  /* VV_NO_SANITIZE_INTEGER */
#include <string.h>

#define XXH_PRIME64_1  0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2  0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3  0x165667B19E3779F9ULL
#define XXH_PRIME64_4  0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5  0x27D4EB2F165667C5ULL

/* Sprint 117: VV_NO_SANITIZE_INTEGER is provided by include/vv_platform.h.
 * xxh64 relies on intentional unsigned modular arithmetic (overflow
 * and shift-out-of-range bits in the round mixer); the annotation
 * silences -fsanitize=integer false positives in hardened builds. */

/* Sprint 117: prefer the compiler builtin which lowers to a single
 * rotate instruction and does NOT trigger UBSan's shift-base check.
 * Falls back to the manual shift expression on older compilers,
 * still annotated with no_sanitize for hardened builds. */
#if defined(__clang__) && __has_builtin(__builtin_rotateleft64)
#  define XXH_ROTL64(x, r) __builtin_rotateleft64((x), (r))
#elif defined(__GNUC__) && (__GNUC__ >= 7)
   /* GCC 7+ recognizes the manual idiom as a rotate */
#  define XXH_ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))
#else
#  define XXH_ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))
#endif

#if defined(__clang__)
__attribute__((noinline))
#endif
static VV_NO_SANITIZE_INTEGER
uint64_t xxh_rotl64(uint64_t x, int r) { return XXH_ROTL64(x, r); }

static inline VV_NO_SANITIZE_INTEGER
uint64_t xxh_round(uint64_t acc, uint64_t input) {
    acc += input * XXH_PRIME64_2;
    acc  = xxh_rotl64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

static inline VV_NO_SANITIZE_INTEGER
uint64_t xxh_merge_round(uint64_t acc, uint64_t val) {
    val  = xxh_round(0, val);
    acc ^= val;
    acc  = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

static inline VV_NO_SANITIZE_INTEGER
uint64_t xxh_avalanche(uint64_t h64) {
    h64 ^= h64 >> 33; h64 *= XXH_PRIME64_2;
    h64 ^= h64 >> 29; h64 *= XXH_PRIME64_3;
    h64 ^= h64 >> 32;
    return h64;
}

VV_NO_SANITIZE_INTEGER
uint64_t vv_xxh64(const void *data, size_t len, uint64_t seed) {
    /* Empty input has a defined hash and needs no storage. Avoid forming
     * an end pointer from the NULL pointer permitted with zero length. */
    if (len == 0) return xxh_avalanche(seed + XXH_PRIME64_5);
    const uint8_t *p = (const uint8_t *)data;
    size_t remaining = len;
    uint64_t h64;

    if (len >= 32) {
        uint64_t v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
        uint64_t v2 = seed + XXH_PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - XXH_PRIME64_1;

        do {
            uint64_t k; memcpy(&k, p, 8); v1 = xxh_round(v1, k); p += 8;
            memcpy(&k, p, 8); v2 = xxh_round(v2, k); p += 8;
            memcpy(&k, p, 8); v3 = xxh_round(v3, k); p += 8;
            memcpy(&k, p, 8); v4 = xxh_round(v4, k); p += 8;
            remaining -= 32;
        } while (remaining >= 32);

        h64 = xxh_rotl64(v1, 1) + xxh_rotl64(v2, 7) + xxh_rotl64(v3, 12) + xxh_rotl64(v4, 18);
        h64 = xxh_merge_round(h64, v1);
        h64 = xxh_merge_round(h64, v2);
        h64 = xxh_merge_round(h64, v3);
        h64 = xxh_merge_round(h64, v4);
    } else {
        h64 = seed + XXH_PRIME64_5;
    }

    h64 += (uint64_t)len;

    /* Check counts before forming pointers past the available input. */
    while (remaining >= 8) {
        uint64_t k; memcpy(&k, p, 8);
        k *= XXH_PRIME64_2; k = xxh_rotl64(k, 31); k *= XXH_PRIME64_1;
        h64 ^= k; h64 = xxh_rotl64(h64, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        p += 8;
        remaining -= 8;
    }
    while (remaining >= 4) {
        uint32_t k; memcpy(&k, p, 4);
        h64 ^= (uint64_t)k * XXH_PRIME64_1;
        h64 = xxh_rotl64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        p += 4;
        remaining -= 4;
    }
    while (remaining > 0) {
        h64 ^= (*p) * XXH_PRIME64_5;
        h64 = xxh_rotl64(h64, 11) * XXH_PRIME64_1;
        p++;
        remaining--;
    }

    return xxh_avalanche(h64);
}

/* ═══════════════════════════════════════════════════════════════
 * STREAMING XXH64
 * ═══════════════════════════════════════════════════════════════ */

void vv_xxh64_init(vv_xxh64_state_t *s, uint64_t seed) {
    s->v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
    s->v2 = seed + XXH_PRIME64_2;
    s->v3 = seed + 0;
    s->v4 = seed - XXH_PRIME64_1;
    s->total_len = 0;
    s->buf_len = 0;
    s->seed = seed;
}

VV_NO_SANITIZE_INTEGER
void vv_xxh64_update(vv_xxh64_state_t *s, const void *data, size_t len) {
    /* A zero-length update is a no-op and permits a NULL data pointer. */
    if (len == 0) return;
    const uint8_t *p = (const uint8_t *)data;
    size_t remaining = len;
    s->total_len += (uint64_t)len;

    /* Fill buffer if partial data pending */
    if (s->buf_len > 0) {
        size_t fill = 32 - s->buf_len;
        if (fill > len) fill = len;
        memcpy(s->buf + s->buf_len, p, fill);
        s->buf_len += fill;
        p += fill;
        remaining -= fill;
        if (s->buf_len < 32) return; /* still partial */
        /* Process the full 32 bytes */
        uint64_t k;
        memcpy(&k, s->buf + 0,  8); s->v1 = xxh_round(s->v1, k);
        memcpy(&k, s->buf + 8,  8); s->v2 = xxh_round(s->v2, k);
        memcpy(&k, s->buf + 16, 8); s->v3 = xxh_round(s->v3, k);
        memcpy(&k, s->buf + 24, 8); s->v4 = xxh_round(s->v4, k);
        s->buf_len = 0;
    }

    /* Process full 32-byte chunks */
    while (remaining >= 32) {
        uint64_t k;
        memcpy(&k, p + 0,  8); s->v1 = xxh_round(s->v1, k);
        memcpy(&k, p + 8,  8); s->v2 = xxh_round(s->v2, k);
        memcpy(&k, p + 16, 8); s->v3 = xxh_round(s->v3, k);
        memcpy(&k, p + 24, 8); s->v4 = xxh_round(s->v4, k);
        p += 32;
        remaining -= 32;
    }

    /* Buffer trailing bytes */
    if (remaining > 0) {
        memcpy(s->buf + s->buf_len, p, remaining);
        s->buf_len += remaining;
    }
}

VV_NO_SANITIZE_INTEGER
uint64_t vv_xxh64_finalize(const vv_xxh64_state_t *s) {
    uint64_t h64;

    if (s->total_len >= 32) {
        h64 = xxh_rotl64(s->v1, 1) + xxh_rotl64(s->v2, 7)
            + xxh_rotl64(s->v3, 12) + xxh_rotl64(s->v4, 18);
        h64 = xxh_merge_round(h64, s->v1);
        h64 = xxh_merge_round(h64, s->v2);
        h64 = xxh_merge_round(h64, s->v3);
        h64 = xxh_merge_round(h64, s->v4);
    } else {
        h64 = s->seed + XXH_PRIME64_5;
    }

    h64 += s->total_len;

    const uint8_t *p = s->buf;
    size_t remaining = s->buf_len;

    while (remaining >= 8) {
        uint64_t k; memcpy(&k, p, 8);
        k *= XXH_PRIME64_2; k = xxh_rotl64(k, 31); k *= XXH_PRIME64_1;
        h64 ^= k; h64 = xxh_rotl64(h64, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        p += 8;
        remaining -= 8;
    }
    while (remaining >= 4) {
        uint32_t k; memcpy(&k, p, 4);
        h64 ^= (uint64_t)k * XXH_PRIME64_1;
        h64 = xxh_rotl64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        p += 4;
        remaining -= 4;
    }
    while (remaining > 0) {
        h64 ^= (*p) * XXH_PRIME64_5;
        h64 = xxh_rotl64(h64, 11) * XXH_PRIME64_1;
        p++;
        remaining--;
    }

    h64 ^= h64 >> 33; h64 *= XXH_PRIME64_2;
    h64 ^= h64 >> 29; h64 *= XXH_PRIME64_3;
    h64 ^= h64 >> 32;
    return h64;
}
