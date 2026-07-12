/*
 * VaptVupt — Cross-platform portability macros
 *
 * Provides unified abstractions for compiler intrinsics used throughout
 * the codebase. Supports GCC, Clang, MSVC, and Intel compilers.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef VV_PLATFORM_H
#define VV_PLATFORM_H

#include <string.h>
#include <stdint.h>

/* ─── Branch prediction hints ─── */
#if defined(__GNUC__) || defined(__clang__)
  #define VV_LIKELY(x)    __builtin_expect(!!(x), 1)
  #define VV_UNLIKELY(x)  __builtin_expect(!!(x), 0)
#else
  #define VV_LIKELY(x)    (x)
  #define VV_UNLIKELY(x)  (x)
#endif

/* ─── Prefetch hint ─── */
#if defined(__GNUC__) || defined(__clang__)
  #define VV_PREFETCH(p)       __builtin_prefetch((p), 0, 1)
  #define VV_PREFETCH_RW(p)    __builtin_prefetch((p), 1, 1)
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
  #include <emmintrin.h>
  #define VV_PREFETCH(p)       _mm_prefetch((const char*)(p), _MM_HINT_T1)
  #define VV_PREFETCH_RW(p)    _mm_prefetch((const char*)(p), _MM_HINT_T1)
#else
  #define VV_PREFETCH(p)       ((void)0)
  #define VV_PREFETCH_RW(p)    ((void)0)
#endif

/* ─── Always-inline / never-inline ─── */
#if defined(__GNUC__) || defined(__clang__)
  #define VV_ALWAYS_INLINE static inline __attribute__((always_inline))
  #define VV_NOINLINE      __attribute__((noinline))
#elif defined(_MSC_VER)
  #define VV_ALWAYS_INLINE static __forceinline
  #define VV_NOINLINE      __declspec(noinline)
#else
  #define VV_ALWAYS_INLINE static inline
  #define VV_NOINLINE
#endif

/* ─── Unused parameter suppression ─── */
#if defined(__GNUC__) || defined(__clang__)
  #define VV_UNUSED __attribute__((unused))
#else
  #define VV_UNUSED
#endif

/* ─── Portable unaligned load/store via memcpy (compiler optimizes to single instr) ─── */
static inline uint16_t vv_load16(const void *p) {
    uint16_t v; memcpy(&v, p, 2); return v;
}
static inline uint32_t vv_load32(const void *p) {
    uint32_t v; memcpy(&v, p, 4); return v;
}
static inline uint64_t vv_load64(const void *p) {
    uint64_t v; memcpy(&v, p, 8); return v;
}
static inline void vv_store16(void *p, uint16_t v) { memcpy(p, &v, 2); }
static inline void vv_store32(void *p, uint32_t v) { memcpy(p, &v, 4); }
static inline void vv_store64(void *p, uint64_t v) { memcpy(p, &v, 8); }

/* ─── Count trailing zeros (for hash/match optimization) ─── */
#if defined(__GNUC__) || defined(__clang__)
  static inline int vv_ctz32(uint32_t x) { return __builtin_ctz(x); }
  static inline int vv_ctz64(uint64_t x) { return __builtin_ctzll(x); }
#elif defined(_MSC_VER)
  #include <intrin.h>
  static inline int vv_ctz32(uint32_t x) {
      unsigned long idx; _BitScanForward(&idx, x); return (int)idx;
  }
  static inline int vv_ctz64(uint64_t x) {
  #if defined(_M_X64) || defined(_M_ARM64)
      unsigned long idx; _BitScanForward64(&idx, x); return (int)idx;
  #else
      uint32_t lo = (uint32_t)x;
      if (lo) return vv_ctz32(lo);
      return 32 + vv_ctz32((uint32_t)(x >> 32));
  #endif
  }
#else
  static inline int vv_ctz32(uint32_t x) {
      int n = 0; while (!(x & 1)) { x >>= 1; n++; } return n;
  }
  static inline int vv_ctz64(uint64_t x) {
      int n = 0; while (!(x & 1)) { x >>= 1; n++; } return n;
  }
#endif

/* ─── SIMD capability detection macros ─── */
#if defined(__AVX2__)
  #define VV_HAS_AVX2 1
#else
  #define VV_HAS_AVX2 0
#endif

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
  #define VV_HAS_SSE2 1
#else
  #define VV_HAS_SSE2 0
#endif

#if defined(__aarch64__) && defined(__ARM_NEON)
  #define VV_HAS_NEON 1
#else
  #define VV_HAS_NEON 0
#endif

/* Sprint 117: explicit no_sanitize annotation for hardened builds.
 *
 * Several hot paths use intentional unsigned modular arithmetic:
 *   - Knuth multiplicative hashes in the LZ matcher
 *   - xxh64 round mixers (multiplication, left-shift)
 *   - Post-decrement loop guards (uint32_t depth-- > 0)
 *
 * C11 §6.2.5p9 defines unsigned overflow as wraparound, so these are
 * NOT undefined behavior — but `-fsanitize=integer` and the related
 * `-fsanitize=shift-base` flags warn anyway, breaking hardened-build
 * deployments. Apply this attribute to the affected functions to
 * silence the false positives without disabling the checks globally.
 *
 * The annotation is clang-only (gcc has no equivalent and does not
 * accept -fsanitize=integer in the first place). */
#if defined(__clang__) && (__clang_major__ >= 4)
#  define VV_NO_SANITIZE_INTEGER \
     __attribute__((no_sanitize("unsigned-integer-overflow", "shift", "shift-base", "shift-exponent")))
#else
#  define VV_NO_SANITIZE_INTEGER
#endif

#endif /* VV_PLATFORM_H */
