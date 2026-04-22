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
        /* Offset >= 8: can safely copy 8 bytes at a time — each chunk fits
         * within the overlap window without reading unwritten bytes. */
        while (length >= 8) {
            uint64_t v;
            memcpy(&v, src, 8);
            memcpy(dst, &v, 8);
            dst += 8; src += 8; length -= 8;
        }
        while (length-- > 0) *dst++ = *src++;
    } else {
        /* CRITICAL: for offset < 8 the "moderate overlap" 8-byte bulk copy
         * is UNSAFE. Reading 8 bytes at src before writing means we read
         * bytes at positions we're about to write, which may be uninitialized.
         *
         * Example: offset=7, length=8. src = dst-7. Read src[0..7] reads
         * dst[-7..0]. But dst[0] is the first byte we'll WRITE, not a
         * literal we already wrote. Bulk-read gets garbage there, then
         * writes it to dst[7], corrupting position 7.
         *
         * Safe implementation: byte-by-byte, where each write feeds the
         * next read correctly (the classic LZ "self-reference" pattern). */
        for (size_t i = 0; i < length; i++) dst[i] = dst[i - (ptrdiff_t)offset];
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

/* SSE2 path: baseline on all x86-64 CPUs. No runtime check needed.
 * Used when AVX2 is not available at runtime, or when compiled without -mavx2. */
#include <emmintrin.h>  /* SSE2 is guaranteed on x86-64 */

static void copy_fast_sse2(uint8_t *dst, const uint8_t *src, size_t n) {
    while (n >= 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)src);
        _mm_storeu_si128((__m128i *)dst, v);
        dst += 16; src += 16; n -= 16;
    }
    if (n > 0) memcpy(dst, src, n);
}

static void copy_match_sse2(uint8_t *dst, uint32_t offset, size_t length) {
    const uint8_t *src = dst - offset;
    if (offset >= 16) {
        while (length >= 16) {
            __m128i v = _mm_loadu_si128((const __m128i *)src);
            _mm_storeu_si128((__m128i *)dst, v);
            dst += 16; src += 16; length -= 16;
        }
        if (length > 0) memcpy(dst, src, length);
    } else {
        copy_match_scalar(dst, offset, length);
    }
}

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
    /* SSE2 is baseline on all x86-64 — no runtime check needed */
    g_copy_fast  = copy_fast_sse2;
    g_copy_match = copy_match_sse2;
    return;
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
