/* VaptVupt codec — originally Apache-2.0 by Cristian Cezar Moisés
 * Integrated into Zupt — MIT License
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT AND Apache-2.0
 */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif

/*
 * VaptVupt — SIMD-accelerated copy routines
 *
 * Three tiers:
 *   1. AVX2 (x86-64 with runtime detection)
 *   2. NEON (ARM64, compile-time)
 *   3. Scalar fallback (always available)
 *
 * PERFORMANCE-CRITICAL: these are the #1 hotspot in decompression.
 * The literal copy and match copy account for ~60% of decode cycles.
 */

#include "vaptvupt.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════
 * SCALAR FALLBACK (always compiled)
 * ═══════════════════════════════════════════════════════════════ */

static void copy_fast_scalar(uint8_t *dst, const uint8_t *src, size_t n) {
    memcpy(dst, src, n);
}

static void copy_match_scalar(uint8_t *dst, uint32_t offset, size_t length) {
    const uint8_t *src = dst - offset;
    if (offset >= 16) {
        /* Non-overlapping: bulk copy */
        while (length >= 16) {
            memcpy(dst, src, 16);
            dst += 16; src += 16; length -= 16;
        }
        if (length > 0) memcpy(dst, src, length);
    } else if (offset >= 8) {
        /* Moderate overlap (8-15): 8-byte copy is safe since offset >= stride */
        while (length >= 8) {
            uint64_t v;
            memcpy(&v, src, 8);
            memcpy(dst, &v, 8);
            dst += 8; src += 8; length -= 8;
        }
        while (length-- > 0) *dst++ = *src++;
    } else {
        /* Short overlap (1-7): byte-by-byte to handle pattern repeat correctly */
        for (size_t i = 0; i < length; i++) dst[i] = src[i];
    }
}

/* ═══════════════════════════════════════════════════════════════
 * x86-64 AVX2 (guarded by compile-time + runtime detection)
 * ═══════════════════════════════════════════════════════════════ */

#if defined(__x86_64__) || defined(_M_X64)

#include <cpuid.h>

static int vv_has_avx2(void) {
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) return 0;
    return (ebx & (1 << 5)) != 0;  /* AVX2 bit */
}

#ifdef __AVX2__
#include <immintrin.h>

static void copy_fast_avx2(uint8_t *dst, const uint8_t *src, size_t n) {
    while (n >= 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)src);
        _mm256_storeu_si256((__m256i *)dst, v);
        dst += 32; src += 32; n -= 32;
    }
    if (n >= 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)src);
        _mm_storeu_si128((__m128i *)dst, v);
        dst += 16; src += 16; n -= 16;
    }
    if (n > 0) memcpy(dst, src, n);
}

static void copy_match_avx2(uint8_t *dst, uint32_t offset, size_t length) {
    const uint8_t *src = dst - offset;
    if (offset >= 32) {
        while (length >= 32) {
            __m256i v = _mm256_loadu_si256((const __m256i *)src);
            _mm256_storeu_si256((__m256i *)dst, v);
            dst += 32; src += 32; length -= 32;
        }
        if (length >= 16) {
            __m128i v = _mm_loadu_si128((const __m128i *)src);
            _mm_storeu_si128((__m128i *)dst, v);
            dst += 16; src += 16; length -= 16;
        }
        if (length > 0) memcpy(dst, src, length);
    } else {
        /* Fall back to scalar for overlapping copies */
        copy_match_scalar(dst, offset, length);
    }
}
#endif /* __AVX2__ */

#endif /* x86-64 */

/* ═══════════════════════════════════════════════════════════════
 * ARM64 NEON (compile-time detection)
 * ═══════════════════════════════════════════════════════════════ */

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>

static void copy_fast_neon(uint8_t *dst, const uint8_t *src, size_t n) {
    while (n >= 16) {
        uint8x16_t v = vld1q_u8(src);
        vst1q_u8(dst, v);
        dst += 16; src += 16; n -= 16;
    }
    if (n > 0) memcpy(dst, src, n);
}

static void copy_match_neon(uint8_t *dst, uint32_t offset, size_t length) {
    const uint8_t *src = dst - offset;
    if (offset >= 16) {
        while (length >= 16) {
            uint8x16_t v = vld1q_u8(src);
            vst1q_u8(dst, v);
            dst += 16; src += 16; length -= 16;
        }
        if (length > 0) memcpy(dst, src, length);
    } else {
        copy_match_scalar(dst, offset, length);
    }
}
#endif /* ARM64 NEON */

/* ═══════════════════════════════════════════════════════════════
 * RUNTIME DISPATCH (initialized once at first call)
 * ═══════════════════════════════════════════════════════════════ */

typedef void (*copy_fast_fn)(uint8_t *, const uint8_t *, size_t);
typedef void (*copy_match_fn)(uint8_t *, uint32_t, size_t);

static copy_fast_fn  g_copy_fast  = NULL;
static copy_match_fn g_copy_match = NULL;

static void vv_init_simd(void) {
    if (g_copy_fast) return;  /* Already initialized */

#if defined(__x86_64__) || defined(_M_X64)
#ifdef __AVX2__
    if (vv_has_avx2()) {
        g_copy_fast  = copy_fast_avx2;
        g_copy_match = copy_match_avx2;
        return;
    }
#endif
#endif

#if defined(__aarch64__) && defined(__ARM_NEON)
    g_copy_fast  = copy_fast_neon;
    g_copy_match = copy_match_neon;
    return;
#endif

    g_copy_fast  = copy_fast_scalar;
    g_copy_match = copy_match_scalar;
}

void vv_copy_fast(uint8_t *dst, const uint8_t *src, size_t n) {
    if (!g_copy_fast) vv_init_simd();
    g_copy_fast(dst, src, n);
}

void vv_copy_match(uint8_t *dst, uint32_t offset, size_t length) {
    if (!g_copy_match) vv_init_simd();
    g_copy_match(dst, offset, length);
}
