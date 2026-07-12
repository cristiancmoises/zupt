/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * VaptVupt — Encoder v2 (Sprint 1)
 *
 * KEY CHANGES:
 *   1. 5-byte multiply-shift hash (fewer collisions than 4-byte)
 *   2. Rep-match: check 3 recent offsets before hash probe (30% hit rate)
 *   3. Match-skip: after long matches, only insert boundary positions
 *   4. AVX2 match extension: 32 bytes/cycle vs 1 byte/cycle scalar
 *   5. Lazy-2 parsing for balanced mode (check pos+1 AND pos+2)
 *   6. Extreme mode: deeper chains (256) + lazy-2
 */

#include "vaptvupt.h"

#include <stdio.h>
#include "vv_platform.h"
#include "vv_huffman.h"
#include "vv_ans.h"
#include "vv_bcj.h"
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) && defined(__AVX2__)
#include <immintrin.h>
#define VV_ENC_AVX2 1
#else
#define VV_ENC_AVX2 0
#endif

/* ═══════════════════════════════════════════════════════════════
 * SECURE MEMORY ZERO (Sprint 117 — defense in depth)
 *
 * Compiler-resistant memset that the optimizer cannot eliminate
 * even when followed by free(). Used to scrub plaintext-derived
 * working buffers (literals, stripped tokens, ANS scratch) before
 * release back to the heap allocator. Without this, plaintext
 * fragments persist in the heap free-list and may be observable
 * through later allocations or memory disclosure.
 *
 * Implementation strategy:
 *   - Prefer `explicit_bzero` (BSD/glibc 2.25+, guaranteed-secure)
 *   - Fall back to `memset_explicit` (C23)
 *   - Last resort: volatile-pointer memset (compiler cannot
 *     prove the writes are dead)
 * ═══════════════════════════════════════════════════════════════ */

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
#  define VV_HAS_EXPLICIT_BZERO 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  define VV_HAS_EXPLICIT_BZERO 1
#else
#  define VV_HAS_EXPLICIT_BZERO 0
#endif

#if VV_HAS_EXPLICIT_BZERO
/* Forward-declare so we don't have to enable _DEFAULT_SOURCE globally
 * (which would conflict with the strict _POSIX_C_SOURCE=199309L the
 * project sets). The symbol is in libc on supported platforms. */
extern void explicit_bzero(void *s, size_t n);
#endif

static inline void vv_secure_zero(void *buf, size_t len) {
    if (!buf || !len) return;
#if VV_HAS_EXPLICIT_BZERO
    explicit_bzero(buf, len);
#else
    /* Volatile pointer prevents the compiler from concluding the
     * memset is dead and eliminating it. The volatile read of `p`
     * each iteration forces the writes to be observable. */
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) *p++ = 0;
#endif
}

/* Sprint 117: VV_NO_SANITIZE_INTEGER is provided by include/vv_platform.h. */

/* ═══════════════════════════════════════════════════════════════
 * VARINT WRITER
 * ═══════════════════════════════════════════════════════════════ */

static inline size_t write_varint(uint8_t *dst, size_t val) {
    size_t n = 0;
    while (val >= 255) { dst[n++] = 255; val -= 255; }
    dst[n++] = (uint8_t)val;
    return n;
}

/* ═══════════════════════════════════════════════════════════════
 * IMPROVED HASH: 5-byte multiply-shift (safe read pattern)
 *
 * Reads exactly 5 bytes using 4+1 to prevent compiler from
 * widening to an 8-byte load that over-reads the buffer.
 * ═══════════════════════════════════════════════════════════════ */

static inline VV_NO_SANITIZE_INTEGER uint32_t hash5(const uint8_t *p) {
    uint32_t lo;
    memcpy(&lo, p, 4);
    uint64_t v = (uint64_t)lo | ((uint64_t)p[4] << 32);
    /* Shift by (64 - HC_BITS) to get the top HC_BITS of the product */
    return (uint32_t)((v * 889523592379ULL) >> (64 - VV_HC_BITS));
}

/* 4-byte hash for positions near end of buffer */
static inline VV_NO_SANITIZE_INTEGER uint32_t hash4(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return (v * 2654435761u) >> (32 - VV_HC_BITS);
}

/* Safe hash: picks 5-byte or 4-byte depending on remaining bytes */
static inline VV_NO_SANITIZE_INTEGER uint32_t hash_safe(const uint8_t *p, int32_t remain) {
    return (remain >= 5) ? hash5(p) : hash4(p);
}

/* ═══════════════════════════════════════════════════════════════
 * AVX2 MATCH EXTENSION
 *
 * Compare 32 bytes at a time. Returns total match length.
 * ~8× faster than byte-by-byte on data with long matches.
 * ═══════════════════════════════════════════════════════════════ */

static inline int32_t extend_match(const uint8_t *a, const uint8_t *b,
                                    int32_t max_len) {
    int32_t len = 0;

    /* SPRINT 55: 8-byte fast-path check first. On binary content,
     * most matches extend 0-12 bytes past the initial 4-byte compare
     * (chain_match_ex already verified 4 bytes before calling). The
     * AVX2 loop's 32-byte minimum overshoots for these common short
     * matches, wasting a load and movemask on bytes we don't need.
     *
     * Check 8 bytes via scalar xor-ctz first: this resolves the
     * common case in 2-3 uops. On binary fixtures (bash, libc.so.6,
     * python3 extreme+format-v2), measurement shows ~60-75% of
     * extend_match calls return len ≤ 8.
     *
     * Falls through to AVX2 when the 8-byte window fully matches
     * and max_len is ≥ 32, so long-match ratio is preserved. */
    if (max_len >= 8) {
        uint64_t va, vb;
        memcpy(&va, a, 8);
        memcpy(&vb, b, 8);
        uint64_t xor_ab = va ^ vb;
        if (xor_ab) {
            /* Little-endian: byte at position k differs iff bit k*8 set */
            return __builtin_ctzll(xor_ab) >> 3;
        }
        len = 8;
    }
#if VV_ENC_AVX2
    while (len + 32 <= max_len) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + len));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + len));
        __m256i eq = _mm256_cmpeq_epi8(va, vb);
        uint32_t mask = ~(uint32_t)_mm256_movemask_epi8(eq);
        if (mask) return len + (int32_t)vv_ctz32(mask);
        len += 32;
    }
#endif
    /* SPRINT 124: 8-byte xor/ctz stride for the post-8 region. This TU
     * is deliberately built without -mavx2 (baseline portability), so
     * before this loop existed every match longer than 8 bytes extended
     * one byte per iteration — measured at 7-8% of encode wall on
     * long-match corpora. Same technique as the fast path above. */
    while (len + 8 <= max_len) {
        uint64_t va, vb;
        memcpy(&va, a + len, 8);
        memcpy(&vb, b + len, 8);
        uint64_t x = va ^ vb;
        if (x) return len + (__builtin_ctzll(x) >> 3);
        len += 8;
    }
    while (len < max_len && a[len] == b[len]) len++;
    return len;
}

/* Branch-free floor(log2(v)); v=0 maps to 0. */
static inline int enc_ilog2(uint32_t v) {
    return 31 - __builtin_clz(v | 1);
}

/* ═══════════════════════════════════════════════════════════════
 * MATCHER: hash chain with 5-byte hash + rep-match
 * ═══════════════════════════════════════════════════════════════ */


#define VV_HC4_BITS  16
#define VV_HC4_SIZE  (1u << VV_HC4_BITS)

static inline VV_NO_SANITIZE_INTEGER uint32_t hash4_short(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return (v * 2654435761u) >> (32 - VV_HC4_BITS);
}

/* ─── SPRINT 45: Hash3 for format v2 ───────────────────────────
 * When min_match=3 (opts.format_v2), we need to find 3-byte
 * matches that hash5/hash4 cannot surface (both require 4-byte
 * prefix equality before extending). Hash3 uses a 3-byte key
 * with its own table and chain (SEPARATE — never share chain
 * arrays across hash tables per Sprint 14's silent-corruption
 * lesson). Table size is 14 bits = 16K entries = 64 KB, smaller
 * than hash4's 256 KB to account for the lower entropy of
 * 3-byte keys.
 *
 * Enabled only when matcher_t::use_hash3 is set (v2 path).
 * When disabled, table3/hash3_chain are NULL, hash3 insert is
 * skipped, and hash3 probe never runs. Zero cost on v1 path. */
#define VV_HC3_BITS  14
#define VV_HC3_SIZE  (1u << VV_HC3_BITS)

static inline VV_NO_SANITIZE_INTEGER uint32_t hash3_short(const uint8_t *p) {
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
    return (v * 2654435761u) >> (32 - VV_HC3_BITS);
}

typedef struct {
    int32_t *table;        /* Primary hash5: VV_HC_SIZE entries */
    int32_t *chain;        /* Primary chain: window_size entries */
    int32_t *table4;       /* Secondary hash4: VV_HC4_SIZE entries */
    int32_t *hash4_chain;  /* Secondary chain (SEPARATE from primary) */
    int32_t *table3;       /* Tertiary hash3 (v2 only): VV_HC3_SIZE entries, NULL on v1 */
    int32_t *hash3_chain;  /* Tertiary chain (SEPARATE from hash4/primary), NULL on v1 */
    uint32_t chain_mask;
    uint32_t chain_depth;
    uint32_t rep[3];       /* 3 most recent match offsets */
    uint8_t  wlog;         /* Window log: controls max offset distance */
    uint8_t  use_hash4;    /* Enable hash4 fallback (binary data only) */
    uint8_t  use_hash3;    /* Enable hash3 fallback (format v2 only) */
    uint8_t  single_probe; /* SPRINT 58: fast-mode lean match finder.
                            * When set, compress_block uses
                            * single_probe_match (a stripped chain walk:
                            * same depth and match-selection as
                            * chain_match, so output is identical, but
                            * without the priming prefetch and the dead
                            * hash4/hash3 branches). Set ONLY on the real
                            * ULTRA_FAST matcher; left 0 on the
                            * balanced/extreme window-selection trial
                            * matchers so their output stays
                            * bit-identical. */
    uint32_t max_match;    /* Max representable matchlen (65535 for v1,
                            * 65534 for v2: ml_base_v2[35]=32767 with 15
                            * extra bits only reaches 65534). */
    uint32_t accel;        /* Position-skip acceleration factor (0 = off).
                            * When >0, after a run of `f` consecutive
                            * positions with no match, compress_block
                            * advances by 1 + ((f*accel) >> 6) instead of 1,
                            * skipping the hash/insert/rep work on
                            * unmatchable regions. Massively speeds up
                            * encode on incompressible / already-compressed
                            * input (measured ~8-9x on random/gzip data),
                            * with a small ratio cost on compressible data
                            * (so it is opt-in; default 0 keeps output
                            * byte-identical). Skipped positions become
                            * literals; output stays decodable by any
                            * decoder. */
    uint8_t  no_rep;       /* 1 = skip rep-match probing in compress_block.
                            * Measured net-positive on ratio in FAST mode
                            * (no entropy stage, so rep's short-offset code
                            * advantage never materializes; it only perturbs
                            * the greedy parse) and ~10% faster. Opt-in
                            * (--no-rep); default 0 keeps rep enabled and
                            * output byte-identical. */
} matcher_t;

/* SPRINT 93 audit: returns 1 on success, 0 on allocation failure.
 * Callers MUST check the return value — on failure m is left in a
 * partially-initialized state with all pointers either valid or NULL,
 * safe to pass to matcher_free for cleanup.
 *
 * Prior to Sprint 93 this function was void-returning with unchecked
 * mallocs. If allocation failed, the immediately-following memset on
 * the NULL pointer would crash. Sprint 92 audit identified this as a
 * real defect. The fix tolerates allocator failure cleanly. */
static void matcher_free(matcher_t *m); /* fwd decl for cleanup-on-failure */
static int matcher_init(matcher_t *m, uint32_t window_log, uint32_t depth) {
    uint32_t wsz = 1u << window_log;
    /* Initialize ALL pointers to NULL first so matcher_free is safe to
     * call on partial-failure paths. */
    m->table = NULL;
    m->chain = NULL;
    m->table4 = NULL;
    m->hash4_chain = NULL;
    m->table3 = NULL;
    m->hash3_chain = NULL;

    m->table = (int32_t *)malloc(VV_HC_SIZE * sizeof(int32_t));
    m->chain = (int32_t *)malloc(wsz * sizeof(int32_t));
    m->table4 = (int32_t *)malloc(VV_HC4_SIZE * sizeof(int32_t));
    m->hash4_chain = (int32_t *)malloc(wsz * sizeof(int32_t));
    if (!m->table || !m->chain || !m->table4 || !m->hash4_chain) {
        matcher_free(m);
        /* Re-NULL after free so caller's matcher_free is also safe */
        m->table = m->chain = m->table4 = m->hash4_chain = NULL;
        m->table3 = m->hash3_chain = NULL;
        return 0;
    }
    /* hash3 tables allocated lazily only when use_hash3 is enabled.
     * On v1 path (the default), they stay NULL and cost nothing. */
    /* PERF: only the table arrays need to be cleared. chain/hash4_chain
     * are only read via table entries (which are now -1), so stale
     * data in them is unreachable. See matcher_reset for rationale. */
    memset(m->table, 0xFF, VV_HC_SIZE * sizeof(int32_t));
    memset(m->table4, 0xFF, VV_HC4_SIZE * sizeof(int32_t));
    m->chain_mask = wsz - 1;
    m->chain_depth = depth;
    m->rep[0] = m->rep[1] = m->rep[2] = 0;
    m->wlog = (uint8_t)window_log;
    m->use_hash4 = 0;  /* Disabled by default — enabled adaptively for binary */
    m->use_hash3 = 0;  /* Disabled by default — enabled for format v2 */
    m->single_probe = 0; /* Disabled by default — set only for ULTRA_FAST encode */
    m->accel = 0;        /* Position-skip acceleration off by default (opt-in --accel) */
    m->no_rep = 0;       /* rep-match probing on by default (opt-in --no-rep) */
    m->max_match = VV_MAX_MATCH;  /* v1 default, see matcher_set_format_v2 */
    return 1;
}

/* Apply format v2 matcher constraints. Must be called whenever the
 * encoder is producing 'T'-tagged blocks, regardless of whether the
 * hash3 probe is active (the adaptive trial may decide not to enable
 * hash3 on non-binary data, but the ml_base_v2 range cap still
 * applies to every match). */
static void matcher_set_format_v2(matcher_t *m) {
    /* ml_base_v2[35]=32767 with 15 extra bits → max representable
     * matchlen = 32767+32767 = 65534. Without this cap, the matcher
     * can produce 65535-length matches whose extra field (32768)
     * overflows 15 bits → encodes as 0 → decoder reconstructs 32767
     * (short by exactly 32,768 bytes per affected match). Root cause
     * of the python3 multi-block corruption in v2.34.0. */
    m->max_match = 65534;
}

/* Enable hash3 path: allocate tables. Idempotent and cheap to skip. */
static int matcher_enable_hash3(matcher_t *m) {
    if (m->table3) return 1;  /* Already enabled */
    uint32_t wsz = 1u << m->wlog;
    m->table3 = (int32_t *)malloc(VV_HC3_SIZE * sizeof(int32_t));
    m->hash3_chain = (int32_t *)malloc(wsz * sizeof(int32_t));
    if (!m->table3 || !m->hash3_chain) {
        free(m->table3); m->table3 = NULL;
        free(m->hash3_chain); m->hash3_chain = NULL;
        return 0;
    }
    memset(m->table3, 0xFF, VV_HC3_SIZE * sizeof(int32_t));
    m->use_hash3 = 1;
    return 1;
}

static void matcher_free(matcher_t *m) {
    free(m->table); m->table = NULL;
    free(m->chain); m->chain = NULL;
    free(m->table4); m->table4 = NULL;
    free(m->hash4_chain); m->hash4_chain = NULL;
    free(m->table3); m->table3 = NULL;
    free(m->hash3_chain); m->hash3_chain = NULL;
}

/* Reset matcher state without reallocating tables. Used by
 * vv_cstream_reset() for fast per-file reuse.
 *
 * PERF: We only need to clear the `table` and `table4` arrays (the
 * hash → position maps). The `chain` arrays store (pos → earlier
 * pos) links, but those links are only FOLLOWED from table entries.
 * After resetting the tables, any stale chain entries become
 * unreachable. This cuts reset cost from ~1.6 MB of memset to
 * ~1.25 MB (table=1MB + table4=256KB), a ~25% speedup. */
static void matcher_reset(matcher_t *m) {
    memset(m->table, 0xFF, VV_HC_SIZE * sizeof(int32_t));
    memset(m->table4, 0xFF, VV_HC4_SIZE * sizeof(int32_t));
    if (m->table3) memset(m->table3, 0xFF, VV_HC3_SIZE * sizeof(int32_t));
    m->rep[0] = m->rep[1] = m->rep[2] = 0;
    m->use_hash4 = 0;
    /* use_hash3 is NOT reset — it's a caller-opted-in mode flag,
     * not adaptive behavior that should clear on reset. */
}

/* SPRINT 29 (v2.50.3): _fast variant of matcher_insert for use inside
 * bulk-insert loops where the caller has already ensured pos + 5 <= end.
 * Skips both the boundary check and the hash5/hash4 dispatch, going
 * straight to hash5. Used inside the post-match-emit insert loops in
 * compress_block where we already gate on `j <= end - 5`.
 *
 * Saves ~3 instructions per insert (one compare, one branch, one
 * hash_safe dispatch). For dickens at ~2M inserts per encode, that's
 * a measurable win on encode throughput (~+4% on Silesia fast mode,
 * Sprint 29 measurement).
 *
 * SAFETY: caller MUST ensure pos + 5 <= end before calling. No
 * runtime check — undefined behavior if violated. */
static inline void matcher_insert_fast(matcher_t *m, const uint8_t *data,
                                        int32_t pos) {
    uint32_t h = hash5(data + pos);
    m->chain[pos & m->chain_mask] = m->table[h];
    m->table[h] = pos;
    if (m->use_hash4) {
        uint32_t h4 = hash4_short(data + pos);
        m->hash4_chain[pos & m->chain_mask] = m->table4[h4];
        m->table4[h4] = pos;
    }
    if (m->use_hash3) {
        uint32_t h3 = hash3_short(data + pos);
        m->hash3_chain[pos & m->chain_mask] = m->table3[h3];
        m->table3[h3] = pos;
    }
}

static inline void matcher_insert(matcher_t *m, const uint8_t *data,
                                   int32_t pos, int32_t end) {
    if (pos + 4 > end) return;
    uint32_t h = hash_safe(data + pos, end - pos);
    m->chain[pos & m->chain_mask] = m->table[h];
    m->table[h] = pos;
    /* PERF: only maintain hash4 table when it's actually being used.
     * For text/source (use_hash4==0), this saves a hash computation
     * and two memory writes per insert — measurable on insert-heavy
     * workloads (logs, JSON). */
    if (m->use_hash4) {
        uint32_t h4 = hash4_short(data + pos);
        m->hash4_chain[pos & m->chain_mask] = m->table4[h4];
        m->table4[h4] = pos;
    }
    /* SPRINT 45: hash3 insert, only when enabled. Same guard logic
     * as hash4 — zero cost when disabled. */
    if (m->use_hash3) {
        uint32_t h3 = hash3_short(data + pos);
        m->hash3_chain[pos & m->chain_mask] = m->table3[h3];
        m->table3[h3] = pos;
    }
}

/* ─── Rep-match check: O(1), checked BEFORE hash probe ─── */
static inline int32_t try_rep_match(const matcher_t *m, const uint8_t *data,
                                     int32_t pos, int32_t end,
                                     int32_t *rep_idx) {
    /* Primary path: require 4-byte equality. Extends from there. */
    for (int i = 0; i < 3; i++) {
        uint32_t d = m->rep[i];
        if (d == 0 || (uint32_t)pos < d) continue;
        int32_t ref = pos - (int32_t)d;
        uint32_t a, b;
        memcpy(&a, data + pos, 4);
        memcpy(&b, data + ref, 4);
        if (a == b) {
            int32_t max = end - pos;
            if (max > (int32_t)m->max_match) max = (int32_t)m->max_match;
            int32_t len = 4 + extend_match(data + pos + 4, data + ref + 4, max - 4);
            *rep_idx = i;
            return len;
        }
    }
    /* SPRINT 47: format v2 secondary path. When hash3 is active, check
     * if any rep-offset produces a 3-byte rep-match even when the
     * 4-byte compare above fails. Rep-matches have 0 extra offset
     * bits — a 3-byte rep is nearly always a win vs 3 literals, which
     * the 4-byte requirement was blocking. Only runs when use_hash3
     * is on (i.e. format v2 + binary-detected), so text/JSON paths
     * stay bit-identical. */
    if (m->use_hash3 && pos + 3 <= end) {
        for (int i = 0; i < 3; i++) {
            uint32_t d = m->rep[i];
            if (d == 0 || (uint32_t)pos < d) continue;
            int32_t ref = pos - (int32_t)d;
            if (data[pos] == data[ref]
                && data[pos + 1] == data[ref + 1]
                && data[pos + 2] == data[ref + 2]) {
                *rep_idx = i;
                return 3;  /* length-3 rep; caller accepts since min_match=3 */
            }
        }
    }
    return 0;
}

/* ─── Hash chain match: uses 5-byte hash, searches up to chain_depth.
 * If use_hash4 is nonzero AND hash5 finds nothing, fall back to hash4
 * chain for binary/struct coverage. ─── */
static VV_NO_SANITIZE_INTEGER int32_t
chain_match_ex(const matcher_t *m, const uint8_t *data,
               int32_t pos, int32_t end, int32_t *best_off,
               int use_hash4) {
    /* Early exit: we need at least 3 bytes for hash3 probe, 4 for
     * hash4/hash5. Use the looser bound if hash3 is enabled. */
    int32_t min_bytes = m->use_hash3 ? 3 : 4;
    if (pos + min_bytes > end) return 0;

    int32_t best_len = 0;
    *best_off = 0;

    int32_t max_dist = (int32_t)((1u << m->wlog) - 1);
    int32_t limit = pos - max_dist;
    if (limit < 0) limit = 0;

    /* Hash5/hash4 paths require 4 bytes. Skip them if only 3 remain. */
    if (pos + 4 <= end) {

    /* Hoist pos4: never changes during the chain walk */
    uint32_t pos4;
    memcpy(&pos4, data + pos, 4);

    /* Primary hash5 chain traversal.
     *
     * SPRINT 55: 4-way software-pipelined chain walk. Chain traversal
     * is a linked list — each next_ref depends on the previous chain
     * load. This serializes iterations at memory-latency speed (~10
     * ns per cache miss on binary data with poor hash5 locality).
     *
     * By walking the chain 4 links ahead and prefetching ALL of the
     * candidate data arrays AND the next chain slots speculatively,
     * we keep 4+ outstanding memory operations in flight per core.
     * The CPU's out-of-order engine then overlaps the 4 L1 fills,
     * effectively quadrupling match-test throughput on cache-miss-
     * bound workloads (bash, libc, python3).
     *
     * Measured effect: +8-15% encode on binary, ~neutral on text
     * (text already has good locality — fewer cache misses to hide).
     *
     * Safety: the prefetch is speculative ONLY. The actual chain walk
     * still respects the ref validity check before any load. A
     * prefetched ref that turns out to be out-of-range or cycles
     * back just results in a harmless L1 pollution — no OOB read, no
     * data-flow dependency on the prefetched value.
     */
    uint32_t h = hash_safe(data + pos, end - pos);
    int32_t ref = m->table[h];
    uint32_t depth = m->chain_depth;
    uint32_t chain_mask = m->chain_mask;
    int32_t *chain_arr = m->chain;

    /* Pipeline priming: look 4 chain entries ahead. If chain is
     * short, the prefetches become no-ops (chain entries below limit
     * just return -1 or an expired position).
     * SPRINT 124: only prime for deep walks. At depth 4 (fast mode,
     * window trial) the priming loads cost more than the misses they
     * hide — measured 5-8% of fast-mode encode wall. */
    if (depth >= 8 && ref >= limit && ref < pos) {
        __builtin_prefetch(data + ref, 0, 0);
        int32_t r1 = chain_arr[ref & chain_mask];
        if (r1 >= limit && r1 < pos) {
            __builtin_prefetch(data + r1, 0, 0);
            __builtin_prefetch(&chain_arr[r1 & chain_mask], 0, 0);
            int32_t r2 = chain_arr[r1 & chain_mask];
            if (r2 >= limit && r2 < pos) {
                __builtin_prefetch(data + r2, 0, 0);
                __builtin_prefetch(&chain_arr[r2 & chain_mask], 0, 0);
            }
        }
    }

    while (ref >= limit && ref < pos && depth-- > 0) {
        int32_t next_ref = chain_arr[ref & chain_mask];
        /* SPRINT 30 (v2.50.4): prefetch unconditionally. The previous
         * guard `if (next_ref >= limit && next_ref < pos)` cost 2
         * branches per iteration in a hot function (chain_match_ex
         * fires ~2.5M times per 10 MB encode in fast mode; each call
         * walks chain_depth iterations).
         *
         * __builtin_prefetch tolerates any address — a bogus prefetch
         * just becomes harmless L1 pollution. The actual data load
         * (`memcpy(&b, data + ref, 4)`) and chain step still respect
         * the validity invariants. Only the prefetch hint is unguarded.
         *
         * Also removed the redundant `ref >= 0` from the while condition:
         * since `limit >= 0` (clamped at line 410), `ref >= limit` already
         * implies `ref >= 0`.
         *
         * Measured: +2.7% encode on dickens fast (median of 10 runs,
         * interleaved). Marginal on sao (+1.3%) and x-ray (+0.6%) —
         * within measurement noise but directionally consistent. Effect
         * is small because chain_depth=4 in fast mode and modern OoO
         * cores already speculate past the guard's branches. The change
         * still benefits because it (a) strictly removes code, (b) lets
         * the hardware prefetcher start deeper, and (c) simplifies the
         * inner loop for future optimization. */
        __builtin_prefetch(data + next_ref, 0, 0);
        __builtin_prefetch(&chain_arr[next_ref & chain_mask], 0, 0);

        uint32_t b;
        memcpy(&b, data + ref, 4);
        if (pos4 == b) {
            int32_t max = end - pos;
            if (max > (int32_t)m->max_match) max = (int32_t)m->max_match;
            int32_t len = 4 + extend_match(data + pos + 4, data + ref + 4, max - 4);
            if (len > best_len) {
                /* SPRINT 124: offset-cost-aware acceptance. The walk
                 * goes newest→oldest, so a later candidate always has
                 * a larger offset. SEQ codes offsets as log2 buckets +
                 * extra bits, so the farther match costs ~dbits more;
                 * each extra matched byte saves ~6 bits of literals.
                 * Without this check a barely-longer match at 512 KB
                 * displaces a same-ish match at 200 B, and the diverse
                 * offsets also break rep-offset streaks downstream.
                 * Only affects greedy/lazy paths — the optimal parser
                 * collects candidates via opt_collect and prices
                 * offsets itself. */
                if (best_len >= 4) {
                    int dbits = enc_ilog2((uint32_t)(pos - ref))
                              - enc_ilog2((uint32_t)*best_off);
                    if ((len - best_len) * 6 < dbits) { ref = next_ref; continue; }
                }
                best_len = len;
                *best_off = pos - ref;
                if (len >= 256) return best_len;
            }
        }
        ref = next_ref;
    }

    /* PERF: Secondary hash4 chain fallback — ONLY when hash5 found nothing
     * AND caller indicates hash4 is safe to use (no competing rep-match).
     * Uses SEPARATE hash4_chain array.
     *
     * Note: tried relaxing trigger to `best_len < 8` in sprint 41 but
     * empirically found NO improvement on real binary data (bash, ls,
     * python3, libc.so.6). The hash4 fallback finds the same matches
     * hash5 already finds when primary prefix is 5 bytes. Closing the
     * binary-compression gap vs gzip-9 (~11% worse) requires either
     * min_match=3 (format change) or deeper LZ-optimal parsing. Kept
     * the zero-only trigger which matches lz4's fallback pattern. */
    if (use_hash4 && best_len == 0) {
        uint32_t h4 = hash4_short(data + pos);
        int32_t ref4 = m->table4[h4];
        uint32_t depth4 = 8;

        if (ref4 >= limit && ref4 < pos) {
            __builtin_prefetch(data + ref4, 0, 0);
        }

        while (ref4 >= limit && ref4 < pos && depth4-- > 0) {
            int32_t next_ref4 = m->hash4_chain[ref4 & m->chain_mask];
            /* SPRINT 30: unconditional prefetch (same rationale as
             * the hash5 walk above). */
            __builtin_prefetch(data + next_ref4, 0, 0);
            __builtin_prefetch(&m->hash4_chain[next_ref4 & m->chain_mask], 0, 0);

            uint32_t b4;
            memcpy(&b4, data + ref4, 4);
            if (pos4 == b4) {
                int32_t max = end - pos;
                if (max > (int32_t)m->max_match) max = (int32_t)m->max_match;
                int32_t len = 4 + extend_match(data + pos + 4, data + ref4 + 4, max - 4);
                if (len > best_len) {
                    /* Same offset-cost-aware acceptance as the hash5 walk. */
                    if (best_len >= 4) {
                        int dbits = enc_ilog2((uint32_t)(pos - ref4))
                                  - enc_ilog2((uint32_t)*best_off);
                        if ((len - best_len) * 6 < dbits) { ref4 = next_ref4; continue; }
                    }
                    best_len = len;
                    *best_off = pos - ref4;
                    if (len >= 256) return best_len;
                }
            }
            ref4 = next_ref4;
        }
    }

    }  /* end if (pos + 4 <= end) */

    /* ─── SPRINT 45: Tertiary hash3 probe ───────────────────────
     * Only when use_hash3 is enabled (format v2) AND hash5/hash4
     * found nothing ≥ 4 bytes (best_len < 4). Uses a SEPARATE
     * chain array from hash4 — never share chain storage.
     *
     * Probe depth is intentionally small (4). Unlike hash4, hash3's
     * collision rate is high (16K entries for up to 16M unique
     * 3-byte keys), so deep walks waste cycles on spurious hits.
     *
     * Match length is reported honestly — may be 3, or may extend.
     * The caller (compress_block) accepts len ≥ min_match. */
    if (m->use_hash3 && best_len < 4 && pos + 3 <= end) {
        uint32_t h3 = hash3_short(data + pos);
        int32_t ref3 = m->table3[h3];
        uint32_t depth3 = 4;

        /* Compare key: the 3 bytes at pos. Pack into low 24 bits
         * of a uint32 for a single compare against the candidate. */
        uint32_t pos3 = (uint32_t)data[pos]
                      | ((uint32_t)data[pos + 1] << 8)
                      | ((uint32_t)data[pos + 2] << 16);

        while (ref3 >= 0 && ref3 >= limit && ref3 < pos && depth3-- > 0) {
            int32_t next_ref3 = m->hash3_chain[ref3 & m->chain_mask];

            uint32_t b3 = (uint32_t)data[ref3]
                        | ((uint32_t)data[ref3 + 1] << 8)
                        | ((uint32_t)data[ref3 + 2] << 16);
            if (pos3 == b3) {
                int32_t max = end - pos;
                if (max > (int32_t)m->max_match) max = (int32_t)m->max_match;
                int32_t len = 3 + extend_match(data + pos + 3, data + ref3 + 3, max - 3);
                /* SPRINT 48: extended offset filter for length-3 hash3
                 * matches. Flat ≤4096 threshold. Higher than v2.35.0's
                 * ≤256 — the v2.36.0 adaptive hash3 gate now keeps
                 * text/JSON fully neutral at ANY threshold, so the
                 * filter only governs binary precision.
                 *
                 * Measured threshold sweep (binary Δ vs V1):
                 *    256 (v2.37): bash -2.2% ls -3.3% libc -2.8% py -5.5%
                 *   1024:         bash -3.4% ls -3.3% libc -3.3% py -6.1%
                 *   4096 (v2.38): bash -3.8% ls -3.9% libc -3.9% py -6.4%
                 *   8192+:        plateau (noise-level changes)
                 *
                 * Text/JSON/source at 0/0/+0.1% across the entire
                 * sweep — the adaptive gate does its job.
                 *
                 * Rejected designs:
                 *   - Sliding threshold (≤128 always, ≤512 if rep):
                 *     tightening to 128 lost more binary gain than
                 *     rep-aware loosening recovered. See CHANGELOG.
                 *   - ANS_LOG 12→10 (Sprint A candidate): predicted
                 *     2-4× text decode; measured 2-6%. Not worth the
                 *     format change. See CHANGELOG v2.38.0 dead-ends.
                 *
                 * Longer matches (len ≥ 4) are always accepted at any
                 * offset (the filter only gates len==3). */
                int32_t off3 = pos - ref3;
                if (len == 3 && off3 > 4096) {
                    ref3 = next_ref3;
                    continue;
                }
                if (len > best_len) {
                    best_len = len;
                    *best_off = off3;
                    if (len >= 8) break;  /* Good enough — don't keep walking */
                }
            }
            ref3 = next_ref3;
        }
    }

    return best_len;
}

static int32_t chain_match(const matcher_t *m, const uint8_t *data,
                            int32_t pos, int32_t end, int32_t *best_off) {
    return chain_match_ex(m, data, pos, end, best_off, m->use_hash4);
}

/* ─── SPRINT 58: lean fast-mode match finder (ULTRA_FAST encode) ─────
 * A stripped-down chain walk for fast mode. It walks the same hash5
 * chain to the same depth as chain_match (m->chain_depth == 4 for fast
 * mode) and selects the match by the same rule (first strictly-longest,
 * early-out at len >= 256), so it produces BYTE-IDENTICAL output to the
 * pre-Sprint-58 chain_match on fast-mode input — verified on all 12
 * Silesia fixtures. The speed comes purely from what it omits on the
 * per-position hot path:
 *   - the 4-way software-pipelined priming prefetch block,
 *   - the per-iteration unconditional prefetches,
 *   - the (always-false in fast mode) hash4 and hash3 fallback branches.
 * Measured fast-mode encode: +9-12% on dickens/xml/samba, with decode
 * and ratio unchanged (output is identical). The change is measured byte-identical (ratio gate +/- 0).
 *
 * A depth-1 (true lz4-style single-probe) and a depth-2/3 sweep were
 * measured and REJECTED: lowering the depth raises encode further but
 * degrades BOTH ratio and decode (shorter matches → more tokens/byte →
 * slower decode), trading the two metrics the SPEED PROGRAM ranks above
 * encode. depth-4 is the only point that improves encode at zero cost.
 *
 * Used by compress_block ONLY when m->single_probe is set, which is
 * ONLY the real ULTRA_FAST matcher. The balanced/extreme window trial
 * matchers keep single_probe==0 and use chain_match, so their output is
 * bit-identical to before this sprint.
 *
 * Returns match length (>= VV_MIN_MATCH on hit, 0 on miss) and writes
 * the offset to *best_off. The 4-byte compare plus extend_match verify
 * actual byte equality, so the emitted match is always decode-correct
 * regardless of hash collisions. */
static VV_NO_SANITIZE_INTEGER int32_t
single_probe_match(const matcher_t *m, const uint8_t *data,
                   int32_t pos, int32_t end, int32_t *best_off) {
    *best_off = 0;
    if (pos + 4 > end) return 0;

    int32_t max_dist = (int32_t)((1u << m->wlog) - 1);
    int32_t limit = pos - max_dist;
    if (limit < 0) limit = 0;

    uint32_t h = hash_safe(data + pos, end - pos);
    int32_t ref = m->table[h];

    uint32_t pos4;
    memcpy(&pos4, data + pos, 4);

    int32_t best_len = 0;
    uint32_t depth = m->chain_depth;        /* same depth as chain_match (4 for fast) */
    uint32_t chain_mask = m->chain_mask;
    const int32_t *chain_arr = m->chain;
    int32_t mm = (int32_t)m->max_match;

    while (ref >= limit && ref < pos && depth-- > 0) {
        int32_t next_ref = chain_arr[ref & chain_mask];
        uint32_t b;
        memcpy(&b, data + ref, 4);
        if (pos4 == b) {
            int32_t max = end - pos;
            if (max > mm) max = mm;
            int32_t len = 4 + extend_match(data + pos + 4, data + ref + 4, max - 4);
            if (len > best_len) {
                best_len = len;
                *best_off = pos - ref;
                if (len >= 256) break;
            }
        }
        ref = next_ref;
    }
    return best_len;
}

/* Update rep offsets (push new offset, shift others down) */
static inline void update_rep(matcher_t *m, uint32_t offset) {
    if (offset == m->rep[0]) return;
    m->rep[2] = m->rep[1];
    m->rep[1] = m->rep[0];
    m->rep[0] = offset;
}

/* ═══════════════════════════════════════════════════════════════
 * EMIT TOKEN (unchanged from v0.1)
 * ═══════════════════════════════════════════════════════════════ */

static size_t emit_seq(uint8_t *dst, const uint8_t *lits,
                        size_t ll, size_t ml, uint32_t off, int off_bytes,
                        int min_match) {
    uint8_t *op = dst;

    uint8_t ll_f = (ll >= 15) ? 15 : (uint8_t)ll;
    uint8_t ml_f;
    if (ml == 0) { ml_f = 0; }
    else { size_t v = ml - (size_t)min_match; ml_f = (v >= 15) ? 15 : (uint8_t)v; }

    *op++ = (ll_f << 4) | ml_f;

    if (ll >= 15) op += write_varint(op, ll - 15);
    if (ll > 0) { memcpy(op, lits, ll); op += ll; }

    if (ml > 0) {
        /* PERF: 2-byte offset for wlog≤16, 3-byte for wlog>16 */
        if (off_bytes == 3) {
            op[0] = (uint8_t)(off);
            op[1] = (uint8_t)(off >> 8);
            op[2] = (uint8_t)(off >> 16);
            op += 3;
        } else {
            vv_write16(op, (uint16_t)off); op += 2;
        }
        if (ml - (size_t)min_match >= 15)
            op += write_varint(op, ml - (size_t)min_match - 15);
    }
    return (size_t)(op - dst);
}

/* ═══════════════════════════════════════════════════════════════
 * SPRINT 42/43: OPTIMAL PARSE (extreme mode only) — RATIO PROGRAM
 *
 * Whole-block forward DP. price[i] = min bits to encode src[start..start+i).
 * Matches are SINGLE edges i -> i+len (no windowing, no truncation), which
 * is what makes long-match data (mozilla/nci) compress correctly: a long
 * match stays one cheap token.
 *
 * Block size is bounded at VV_MAX_BLOCK_SIZE (1 MB), so price[block_len+1]
 * (int32) is at most ~4 MB — affordable per block.
 *
 * WIRE FORMAT NEUTRAL: emits the same (ll, mlen, moff) token stream that
 * emit_seq consumes. Verified byte-perfect roundtrip on all fixtures.
 * GATED TO EXTREME MODE: balanced/fast keep greedy/lazy.
 * ═══════════════════════════════════════════════════════════════ */

#define VV_OPT_MAX_CAND  16
#define VV_OPT_PRICE_INF 0x3FFFFFFF

typedef struct { uint32_t off; int32_t len; } opt_cand_t;

/* literal bit price (~6 bits/byte, formalizes Sprint 119 lazy model) */
/* Sprint 44: literal price 8 bits/byte (was 6 in v2.51.0).
 *
 * Sweep across full Silesia at extreme mode found litp=8 minimizes
 * aggregate compressed size:
 *
 *   litp   aggregate vs v2.50.11 baseline
 *   6      -2.75% geomean (v2.51.0 default)
 *   7      -3.45%
 *   8      -3.64%  ← chosen
 *   9      -3.50%
 *
 * The flat-6 model under-priced literals: 4-stream Huffman delivers ~6
 * bits/byte on text but 7-8 bits/byte on dense binary (sao, x-ray,
 * mozilla). Raising the constant to 8 makes the parser less willing to
 * substitute a near-match for a literal run on dense data without
 * sacrificing text wins. Result vs v2.51.0: 10/12 fixtures improve, only
 * nci slightly worse (nci exceeds the 16 MB window; addressed in a
 * future window-size sprint).
 *
 * A future refinement is true per-byte Huffman costs from a first parse
 * pass (two-pass repricing) — that would let the parser exploit
 * byte-frequency skew within a block. Empirically the flat constant
 * captures most of the available win at zero added complexity, so this
 * sprint ships it and defers the two-pass design until the window-size
 * lever has been measured (matters more for nci-class fixtures). */
static inline int32_t opt_lit_price(void) { return 8; }

/* SPRINT 129: per-byte literal prices from the block's byte histogram.
 * The flat-8 model (Sprint 44) was chosen as the best single constant,
 * but the real literal coder delivers ~4-6 bits/byte on text and 7-8
 * on dense binary — the flat constant over-prices text literals, so
 * the parser substitutes marginal matches where literals are cheaper
 * in reality. This is the "two-pass repricing" refinement that Sprint
 * 44's note deferred, using the raw block histogram as the literal-
 * distribution estimate (the true literal stream excludes match-
 * covered bytes, but the distributions track closely in practice).
 * price[b] = round(log2(N / hist[b])) clamped to [VV_OPT_LIT_MIN, 14];
 * unseen bytes cannot appear as literals and get the ceiling. The
 * clamp floor guards degenerate blocks (a byte at ~100% frequency
 * would price to 0 and make literal runs look free). Constants swept
 * on the 11-file corpus — see CHANGELOG v2.64.0. */
#ifndef VV_OPT_LIT_MIN
#define VV_OPT_LIT_MIN 2
#endif
#ifndef VV_OPT_LIT_BLEND
#define VV_OPT_LIT_BLEND 6
#endif
/* fwd decl: the greedy parser (defined below) doubles as the residual-
 * literal estimator for the optimal parser's pricing prepass. */
static size_t compress_block(const uint8_t *src, size_t start_pos, size_t block_len,
                             uint8_t *dst, size_t dst_cap,
                             matcher_t *m, vv_mode_t mode, int min_match);

/* SPRINT 130: histogram the literal bytes of an LZ token stream (the
 * residual literals a parse actually leaves), walking the same wire
 * layout extract_literals does but only counting. Returns total
 * literal count, or 0 on a malformed stream (caller falls back to the
 * raw-block histogram). */
static size_t tok_lit_hist(const uint8_t *tokens, size_t tok_len,
                           int off_bytes, uint32_t hist[256]) {
    const uint8_t *tp = tokens, *tp_end = tokens + tok_len;
    size_t total = 0;
    while (tp < tp_end) {
        uint8_t token = *tp++;
        size_t ll = token >> 4;
        size_t mc = token & 0x0F;
        if (ll == 15) {
            do {
                if (tp >= tp_end) return 0;
                uint8_t b = *tp++;
                ll += b;
                if (b < 255) break;
            } while (tp < tp_end);
        }
        if ((size_t)(tp_end - tp) < ll) return 0;
        for (size_t i = 0; i < ll; i++) hist[tp[i]]++;
        total += ll;
        tp += ll;
        if (tp >= tp_end) break;
        if ((size_t)(tp_end - tp) < (size_t)off_bytes) return 0;
        tp += off_bytes;
        if (mc == 15) {
            do {
                if (tp >= tp_end) return 0;
                uint8_t b = *tp++;
                if (b < 255) break;
            } while (tp < tp_end);
        }
    }
    return total;
}

static void opt_build_lit_prices_from_hist(const uint32_t hist[256], size_t n,
                                           int32_t lit_bits[256]) {
    for (int s = 0; s < 256; s++) {
        if (!hist[s] || !n) { lit_bits[s] = 14; continue; }
        /* ratio8 = (n / hist[s]) in 24.8 fixed point; log2(ratio8) =
         * log2(n/hist) + 8. Round via the mantissa bit below the MSB. */
        uint32_t ratio8 = (uint32_t)(((uint64_t)n << 8) / hist[s]);
        int t = enc_ilog2(ratio8);
        int bits = t - 8;
        if (t >= 1 && ((ratio8 >> (t - 1)) & 1)) bits++;   /* round half up */
        if (bits < VV_OPT_LIT_MIN) bits = VV_OPT_LIT_MIN;
        if (bits > 14) bits = 14;
        /* Blend toward the flat-8 prior: a histogram estimate is still
         * an approximation of the coder's delivered cost, and pricing
         * from it unblended over-buys literals (measured; see the
         * v2.64.0 sweep). blend/8 parts per-byte estimate, rest flat. */
        lit_bits[s] = (VV_OPT_LIT_BLEND * bits + (8 - VV_OPT_LIT_BLEND) * 8) / 8;
    }
}

/* match bit price: cost_const(14) + log2(off) + ml_extra; rep ~2 bits.
 *
 * SPRINT 128: priced against a caller-supplied rep set instead of
 * m->rep. The matcher's rep state is a greedy-parser search heuristic
 * that nothing updates during an optimal parse (it stayed {0,0,0} for
 * every all-extreme frame, so rep pricing here was dead code), and the
 * wire's rep state is PER-BLOCK and PATH-DEPENDENT: the SEQ encoder
 * and decoder both start each block at {0,0,0} and evolve it per
 * emitted sequence. The DP now threads that exact state through
 * per-position rep histories (see compress_block_optimal). */
/* A rep match saves the offset EXTRA bits, not the per-sequence
 * overhead: it still spends full LL/OF/ML code symbols (~10 bits).
 * The explicit-match constant 14 approximates that overhead plus
 * slack, so the rep price must stay close beneath it — pricing reps
 * near-free makes the DP shred long matches into chains of short rep
 * matches, each paying the un-modeled sequence overhead (measured:
 * -15% ratio on logs at rep=2). Constant swept on the 11-file corpus. */
#ifndef VV_OPT_REP_BITS
#define VV_OPT_REP_BITS 10
#endif
static inline int32_t opt_match_price(const uint32_t reps[3], uint32_t off, int32_t len) {
    int is_rep = (off == reps[0] || off == reps[1] || off == reps[2]);
    int32_t log2_off = 0; uint32_t o = off;
    while (o > 1) { o >>= 1; log2_off++; }
    int32_t off_bits = is_rep ? VV_OPT_REP_BITS : (14 + log2_off);
    int32_t ml_extra = 0, v = len - VV_MIN_MATCH;
    if (v >= 15) ml_extra = 8 * (v / 255 + 1);
    return off_bits + ml_extra;
}

/* Wire rep-history update rule — must mirror vva_encode_sequences'
 * enc_rep update (and the decoder's dec_rep) exactly: push only when
 * the offset differs from rep[0]. */
static inline void opt_rep_push(uint32_t dst[3], const uint32_t src3[3], uint32_t off) {
    if (off == src3[0]) {
        dst[0] = src3[0]; dst[1] = src3[1]; dst[2] = src3[2];
    } else {
        dst[0] = off; dst[1] = src3[0]; dst[2] = src3[1];
    }
}

/* Collect match candidates at pos (longest per distinct offset).
 * SPRINT 128: rep candidates come from the DP path's rep history. */
static int opt_collect(const matcher_t *m, const uint8_t *data,
                       int32_t pos, int32_t end, opt_cand_t *cands,
                       const uint32_t reps[3]) {
    int n = 0;
    int32_t max_dist = (int32_t)((1u << m->wlog) - 1);
    int32_t limit = pos - max_dist; if (limit < 0) limit = 0;
    if (pos + 4 > end) return 0;
    int32_t max = end - pos;
    if (max > (int32_t)m->max_match) max = (int32_t)m->max_match;
    uint32_t pos4; memcpy(&pos4, data + pos, 4);

    for (int r = 0; r < 3; r++) {
        uint32_t roff = reps[r];
        if (roff == 0 || (int32_t)roff > pos) continue;
        const uint8_t *a = data + pos, *b = data + pos - roff;
        int32_t l = 0; while (l < max && a[l] == b[l]) l++;
        if (l >= VV_MIN_MATCH && n < VV_OPT_MAX_CAND) { cands[n].off = roff; cands[n].len = l; n++; }
    }
    uint32_t h = hash_safe(data + pos, end - pos);
    int32_t ref = m->table[h];
    uint32_t depth = m->chain_depth, chain_mask = m->chain_mask;
    int32_t *chain_arr = m->chain;
    while (ref >= limit && ref < pos && depth-- > 0 && n < VV_OPT_MAX_CAND) {
        uint32_t b; memcpy(&b, data + ref, 4);
        if (pos4 == b) {
            int32_t l = 4 + extend_match(data + pos + 4, data + ref + 4, max - 4);
            uint32_t off = (uint32_t)(pos - ref);
            int dup = 0;
            for (int k = 0; k < n; k++) if (cands[k].off == off) { if (cands[k].len < l) cands[k].len = l; dup = 1; break; }
            if (!dup && l >= VV_MIN_MATCH) { cands[n].off = off; cands[n].len = l; n++; }
        }
        ref = chain_arr[ref & chain_mask];
    }
    return n;
}

static size_t compress_block_optimal(const uint8_t *src, size_t start_pos,
                                     size_t block_len, uint8_t *dst,
                                     size_t dst_cap, matcher_t *m, int min_match) {
    uint8_t *op = dst;
    int32_t base = (int32_t)start_pos;
    int32_t end = (int32_t)(start_pos + block_len);
    int off_bytes = (m->wlog > 16) ? 3 : 2;
    int32_t N = (int32_t)block_len;

    /* DP arrays indexed by offset-from-base [0..N].
     * SPRINT 128: prep[i] is the wire rep-offset history of the best
     * path reaching position i (zstd-btopt-style approximation: paths
     * that lose on price but would carry better reps are dropped).
     * prep[0] = {0,0,0} because the SEQ encoder and decoder both reset
     * their rep state at every block boundary. */
    int32_t  *price = (int32_t *)malloc(sizeof(int32_t) * (N + 1));
    int32_t  *plen  = (int32_t *)malloc(sizeof(int32_t) * (N + 1));
    uint32_t *poff  = (uint32_t *)malloc(sizeof(uint32_t) * (N + 1));
    uint32_t (*prep)[3] = (uint32_t (*)[3])malloc(sizeof(uint32_t[3]) * (N + 1));
    opt_cand_t *cands = (opt_cand_t *)malloc(sizeof(opt_cand_t) * VV_OPT_MAX_CAND);
    if (!price || !plen || !poff || !prep || !cands) { free(price); free(plen); free(poff); free(prep); free(cands); return 0; }

    for (int32_t i = 0; i <= N; i++) { price[i] = VV_OPT_PRICE_INF; plen[i] = 0; poff[i] = 0; }
    price[0] = 0;
    prep[0][0] = prep[0][1] = prep[0][2] = 0;

    /* SPRINT 129/130: entropy-aware per-byte literal prices for this
     * block. The distribution that matters is the RESIDUAL literal
     * stream (bytes a parse leaves uncovered), not the raw block — the
     * raw histogram is dominated by exactly the repetitive content
     * that matches will remove. A depth-4 greedy prepass on a private
     * throwaway matcher (no shared-state pollution, ~1% of the DP's
     * runtime) estimates that stream; its token output is histogrammed
     * and discarded. Falls back to the raw-block histogram if the
     * prepass cannot run. */
    int32_t lit_bits[256];
    {
        uint32_t hist[256];
        memset(hist, 0, sizeof(hist));
        size_t nlit = 0;
        matcher_t mp;
        if (matcher_init(&mp, m->wlog, 4)) {
            mp.accel = 2;
            mp.max_match = m->max_match;
            size_t pcap = block_len + block_len / 255 + 1024;
            uint8_t *ptok = (uint8_t *)malloc(pcap);
            if (ptok) {
                size_t pcsz = compress_block(src, start_pos, block_len, ptok,
                                             pcap, &mp, VV_MODE_ULTRA_FAST, min_match);
                if (pcsz > 0)
                    nlit = tok_lit_hist(ptok, pcsz, off_bytes, hist);
                free(ptok);
            }
            matcher_free(&mp);
        }
        if (nlit == 0) {
            /* Prepass unavailable or block fully covered: raw fallback. */
            memset(hist, 0, sizeof(hist));
            for (int32_t i = 0; i < N; i++) hist[src[base + i]]++;
            nlit = (size_t)N;
        }
        opt_build_lit_prices_from_hist(hist, nlit, lit_bits);
    }

    /* Forward DP. We also must keep the matcher hash chains populated as we
     * advance, so matches reference earlier positions correctly. We insert
     * every position into the matcher as we visit it (DP order = position
     * order since edges only go forward). */
    /* SPRINT 43: work budget. The optimal DP is O(N × chain_depth ×
     * extend). On adversarial self-similar data (long chains + long
     * extends at every position) this degrades to near-quadratic and
     * becomes a DoS vector. We bound total candidate-collection work;
     * if exceeded, bail (return 0) so emit_block falls to greedy/lazy
     * via the raw-store path is NOT what we want — instead we cap by
     * short-circuiting long matches, which both bounds work AND is the
     * correct optimal choice (a very long match is never beaten). */
    const int32_t LONG_MATCH = 512;   /* take immediately, skip interior DP */

    for (int32_t i = 0; i < N; i++) {
        if (price[i] >= VV_OPT_PRICE_INF) {
            matcher_insert(m, src, base + i, end);
            continue;
        }
        int32_t ip = base + i;

        /* literal edge (literals leave the rep history unchanged) */
        int32_t lp = price[i] + lit_bits[src[ip]];
        if (lp < price[i + 1]) {
            price[i + 1] = lp; plen[i + 1] = 1; poff[i + 1] = 0;
            prep[i + 1][0] = prep[i][0]; prep[i + 1][1] = prep[i][1]; prep[i + 1][2] = prep[i][2];
        }

        /* match edges */
        if (ip + min_match <= end) {
            int nc = opt_collect(m, src, ip, end, cands, prep[i]);
            /* Find the longest candidate. */
            int32_t best_len = 0; uint32_t best_off = 0;
            for (int c = 0; c < nc; c++) {
                if (cands[c].len > best_len) { best_len = cands[c].len; best_off = cands[c].off; }
            }
            if (best_len >= LONG_MATCH) {
                /* LONG MATCH SHORT-CIRCUIT: a match this long is never
                 * beaten by any combination of shorter tokens. Take it
                 * as a single edge, skip the per-length relaxation AND
                 * skip DP/insertion for its interior positions. This
                 * bounds worst-case work on repetitive data: instead of
                 * O(match_len) work per interior position, we jump over
                 * the whole match. */
                int32_t use = best_len;
                if (i + use > N) use = N - i;
                int32_t np = price[i] + opt_match_price(prep[i], best_off, use);
                int32_t j = i + use;
                if (np < price[j]) {
                    price[j] = np; plen[j] = use; poff[j] = best_off;
                    opt_rep_push(prep[j], prep[i], best_off);
                }
                /* Insert boundary positions only (match-skip heuristic),
                 * then jump the DP cursor to the match end. */
                int32_t end5 = end - 5;
                for (int32_t q = ip; q < ip + 3 && q <= end5; q++) matcher_insert_fast(m, src, q);
                for (int32_t q = ip + use - 3; q < ip + use && q <= end5; q++) matcher_insert_fast(m, src, q);
                /* Advance i to j-1 (loop ++ makes it j). price[j] is set;
                 * intermediate price[i+1..j-1] stay INF, which is fine —
                 * the backtrack follows plen[] from reachable nodes only. */
                i = j - 1;
                continue;
            }
            for (int c = 0; c < nc; c++) {
                int32_t mlen = cands[c].len; uint32_t moff = cands[c].off;
                if (i + mlen > N) mlen = N - i;
                if (mlen < min_match) continue;
                for (int32_t L = mlen; L >= min_match; L--) {
                    int32_t np = price[i] + opt_match_price(prep[i], moff, L);
                    int32_t j = i + L;
                    if (np < price[j]) {
                        price[j] = np; plen[j] = L; poff[j] = moff;
                        opt_rep_push(prep[j], prep[i], moff);
                    }
                    if (L > min_match + 8 && L < mlen) L = min_match + 9;
                }
            }
        }

        matcher_insert(m, src, ip, end);
    }

    /* Backtrack from N to 0 to recover the token sequence (reverse). */
    /* Worst case every position is a literal: N entries. */
    int32_t *seq_len = (int32_t *)malloc(sizeof(int32_t) * (N + 1));
    uint32_t *seq_off = (uint32_t *)malloc(sizeof(uint32_t) * (N + 1));
    if (!seq_len || !seq_off) { free(price); free(plen); free(poff); free(prep); free(cands); free(seq_len); free(seq_off); return 0; }
    int32_t ns = 0, cur = N;
    while (cur > 0) {
        int32_t L = plen[cur];
        if (L <= 0) L = 1;                 /* safety: treat as literal */
        seq_len[ns] = L; seq_off[ns] = poff[cur]; ns++;
        cur -= L;
    }

    /* Emit forward (reverse the backtrack). Accumulate literals between
     * matches into literal runs, exactly like compress_block. */
    const uint8_t *lit_start = src + base;
    int32_t pos = base;
    for (int k = ns - 1; k >= 0; k--) {
        int32_t L = seq_len[k]; uint32_t O = seq_off[k];
        if (O == 0) {
            pos++;  /* literal: extend pending run */
        } else {
            size_t ll = (size_t)(src + pos - lit_start);
            size_t needed = 1 + (ll >= 15 ? ll / 255 + 2 : 0) + ll + 2 + ((size_t)L / 255 + 2);
            if ((size_t)(op - dst) + needed > dst_cap) {
                free(price); free(plen); free(poff); free(prep); free(cands); free(seq_len); free(seq_off);
                return 0;
            }
            op += emit_seq(op, lit_start, ll, (size_t)L, O, off_bytes, min_match);
            update_rep(m, O);
            pos += L;
            lit_start = src + pos;
        }
    }
    /* trailing literals */
    {
        size_t ll = (size_t)(src + end - lit_start);
        size_t needed = 1 + (ll >= 15 ? ll / 255 + 2 : 0) + ll;
        if ((size_t)(op - dst) + needed > dst_cap) {
            free(price); free(plen); free(poff); free(prep); free(cands); free(seq_len); free(seq_off);
            return 0;
        }
        op += emit_seq(op, lit_start, ll, 0, 0, off_bytes, min_match);
    }

    free(price); free(plen); free(poff); free(prep); free(cands); free(seq_len); free(seq_off);
    return (size_t)(op - dst);
}

/* ═══════════════════════════════════════════════════════════════
 * COMPRESS BLOCK: greedy / lazy / lazy-2
 *
 * Match-skip heuristic: after a match of length ≥ 16, only insert
 * the last 3 positions into the hash chain. The interior positions
 * are inside the match and won't be needed. This saves O(match_len)
 * hash insertions, speeding up compression by 15-25% at L3+.
 * ═══════════════════════════════════════════════════════════════ */

static size_t compress_block(const uint8_t *src, size_t start_pos, size_t block_len,
                             uint8_t *dst, size_t dst_cap,
                             matcher_t *m, vv_mode_t mode, int min_match) {
    uint8_t *op = dst;
    int32_t pos = (int32_t)start_pos;
    int32_t end = (int32_t)(start_pos + block_len);
    const uint8_t *lit_start = src + start_pos;
    int off_bytes = (m->wlog > 16) ? 3 : 2;
    uint32_t failures = 0; /* consecutive no-match positions (for accel skip) */
    uint32_t nmatch = 0;   /* matches found in this block (early-RAW bail) */

    while (pos < end - min_match) {
        int32_t mlen = 0, moff = 0;
        int pos_inserted = 0;

        /* ─── Step 1: Try rep-match (free, no hash lookup) ─── */
        int32_t rep_idx = -1;
        int32_t rep_len = m->no_rep ? 0 : try_rep_match(m, src, pos, end, &rep_idx);

        if (rep_len >= min_match) {
            mlen = rep_len;
            moff = (int32_t)m->rep[rep_idx];
        }

        /* ─── Step 2: Hash chain match (only if rep didn't find a long one) ─── */
        if (mlen < 8) {
            int32_t chain_off = 0;
            /* SPRINT 58: fast mode (single_probe) uses the lean
             * finder; balanced/extreme use the full chain walk. The
             * branch is on a matcher flag set only for the real
             * ULTRA_FAST encode, so balanced/extreme (and the window-
             * selection trial) take the chain_match path exactly as
             * before — bit-identical output. The lean finder selects
             * the same match as chain_match at the same depth, so
             * fast-mode output is unchanged too; only the per-position
             * search overhead drops. */
            int32_t chain_len = m->single_probe
                ? single_probe_match(m, src, pos, end, &chain_off)
                : chain_match(m, src, pos, end, &chain_off);
            if (chain_len > mlen) {
                mlen = chain_len;
                moff = chain_off;
                rep_idx = -1; /* not a rep match */
            }
        }

        /* ─── Step 3: Lazy evaluation (balanced + extreme) ─── */
        /* Sprint 121: gate lazy probing on `mlen < 8`. Counterintuitive
         * but empirically validated: the cost-aware lazy decision
         * (added Sprint 120) makes WORSE choices when the current match
         * is already moderately long.
         *
         * Why: cost-aware lazy compares per-byte costs of competing
         * matches. When mlen ≥ 8, the current match's per-byte cost is
         * already low (≈1.5–3 bits/byte for typical offsets). A lazy
         * probe at pos+1 finding a slightly longer match at a different
         * offset triggers a shift, paying 1 literal but only marginally
         * improving per-byte cost. The literal cost dominates the small
         * per-byte gain, AND the cost-model approximation accumulates
         * error that biases toward shifting.
         *
         * Empirical sweep on the 8-fixture suite (aggregate Δ vs zstd-3):
         *   no gate (lazy always):  −0.130%   (v2.48.0 / Sprint 120)
         *   mlen < 16:              −0.252%
         *   mlen < 12:              −0.386%
         *   mlen <  9:              −0.776%
         *   mlen <  8:              −1.070%   (THIS)
         *   mlen <  7:              −1.282%
         *   mlen <  6:              −1.860%
         *   mlen <  5:              −2.044%   (best aggregate, but
         *                                       fx_json regresses 8.5pp)
         *   no lazy (mlen < 4):     −0.921%
         *
         * The mlen<5 setting wins aggregate but breaks fx_json from
         * −2.49% to +6.04% — unacceptable per-fixture regression.
         * mlen<8 is the safe optimum: improves every fixture vs v2.48.0
         * with no regressions. */
        if (mode >= VV_MODE_BALANCED && mlen >= min_match && mlen < 8 &&
            pos + 1 < end - min_match) {
            /* Check pos+1 */
            matcher_insert(m, src, pos, end);
            pos_inserted = 1;
            int32_t noff = 0;
            int32_t nlen = chain_match(m, src, pos + 1, end, &noff);

            /* Also check rep at pos+1 */
            int32_t nri = -1;
            int32_t nrl = m->no_rep ? 0 : try_rep_match(m, src, pos + 1, end, &nri);
            if (nrl > nlen && nri >= 0) { nlen = nrl; noff = (int32_t)m->rep[nri]; }

            /* SPRINT 119: cost-aware lazy decision (closes the +1.2%
             * ratio gap to zstd-3 — see CHANGELOG.md, Sprint 120).
             *
             * Old code used `nlen > mlen + 2` which ignores offset cost.
             * This made vv prefer shorter matches at far offsets over
             * longer matches at near offsets. zstd-3 produces ~11% fewer
             * sequences on dickens (1.22M vs 1.37M) by accounting for
             * offset cost when choosing between competing matches.
             *
             * Cost model:
             *   match_bits(off, len) ≈ 10 + log2(off) + ml_extra(len)
             *     - 10 covers ML/OF/LL ANS code values (avg ~3 bits each)
             *     - log2(off) is the OF extra-bit cost (info-theoretic min)
             *     - ml_extra is small for short matches (0 for len ≤ 19)
             *   literal_bits ≈ 6 (4-stream Huffman avg on text)
             *
             * Decide on B (shift) over A (emit current match) when:
             *   (literal_bits + match_bits(noff, nlen)) / (nlen + 1)
             *     < match_bits(moff, mlen) / mlen
             *
             * Rep matches have offset cost ≈ 1 bit (rep code, no extras),
             * so they're heavily favored regardless of length. */
            if (nlen >= min_match) {
                /* Approx log2(off) — clamp to 1 for rep candidates and
                 * to >= 1 generally to avoid div-by-zero quirks. */
                int log2_moff = 0; uint32_t mo = (uint32_t)moff;
                while (mo > 1) { mo >>= 1; log2_moff++; }
                int log2_noff = 0; uint32_t no = (uint32_t)noff;
                while (no > 1) { no >>= 1; log2_noff++; }

                /* Rep matches use 0 extra bits but do consume an OF code
                 * slot. Approximate them as cost 2 bits regardless of
                 * the actual offset value.
                 *
                 * Sprint 121: per-mode constant. Extreme mode (deep
                 * chain search) optimizes at +14; balanced mode
                 * (shallow chain) optimizes at +18 because the lazy
                 * candidates from a depth-24 search are noisier and
                 * benefit from less aggressive shifting. */
                int cost_const = (mode >= VV_MODE_EXTREME) ? 14 : 18;
                int moff_bits = (rep_idx >= 0) ? 2 : (cost_const + log2_moff);
                int noff_bits = (nri >= 0)     ? 2 : (cost_const + log2_noff);

                /* Cross-multiply to avoid floating-point in hot path:
                 *   (literal_bits + noff_bits) * mlen < moff_bits * (nlen + 1) */
                int literal_bits = 6;
                int lhs = (literal_bits + noff_bits) * mlen;
                int rhs = moff_bits * (nlen + 1);
                if (lhs < rhs) {
                    pos++;
                    pos_inserted = 0;  /* the inserted position is now pos-1 */
                    mlen = nlen; moff = noff;
                    rep_idx = nri;  /* may have shifted from explicit→rep or vice versa */

                    /* SPRINT 121: cost-aware lazy-2 was tested and rejected.
                     * Measured Δ vs lazy-1-only (gate mlen<8 in both cases):
                     *   fx_text:    neutral
                     *   fx_json:    −0.003% (negligible)
                     *   fx_source:  +0.022%
                     *   bash:       −0.052%
                     *   dickens:    +0.912%   ← significant regression
                     *   xml:        +0.086%
                     *   sao:        +0.874%   ← significant regression
                     *   x-ray:      +0.361%
                     *   AGGREGATE:  +0.601% (worse)
                     *
                     * The shift cascade dominates: after a successful
                     * lazy-1 shift, a second probe at the new pos+1
                     * tends to find marginally-longer matches and
                     * shifts again, eating literals faster than the
                     * cost model accounts for. The cost-model error
                     * compounds with each shift.
                     *
                     * Lazy-1 captures the available benefit cleanly. */
                }
            }
        }

        /* ─── Step 4: Emit sequence or literal ─── */
        if (mlen >= min_match) {
            size_t ll = (size_t)(src + pos - lit_start);
            size_t needed = 1 + (ll >= 15 ? ll / 255 + 2 : 0)
                          + ll + 2 + ((size_t)mlen / 255 + 2);
            if ((size_t)(op - dst) + needed > dst_cap) return 0;

            op += emit_seq(op, lit_start, ll, (size_t)mlen, (uint32_t)moff, off_bytes, min_match);

            /* ─── Hash insertion with skip heuristic ─── */
            /* SPRINT 29: use matcher_insert_fast inside the bulk loops
             * (skips per-iteration hash_safe dispatch and boundary
             * check). Bound is `j + 5 <= end` so hash5 is always safe.
             * Positions in [end-4, end) are not inserted by this loop;
             * for typical block sizes (64KB+) the missed boundary
             * position is negligible (1 position).
             *
             * Saves ~3 instructions per insert. Measured +4% encode
             * speedup on Silesia fast mode (Sprint 29). */
            /* SPRINT 124: when the lazy probe already inserted pos and
             * we did not shift, start at pos+1 — re-inserting pos would
             * put a self-duplicate link in the chain, lengthening every
             * future walk through that bucket. */
            int32_t ins_first = pos + (pos_inserted ? 1 : 0);
            if (mlen >= 16) {
                /* Long match: only insert boundary positions */
                int32_t end5 = end - 5;
                for (int32_t j = ins_first; j < pos + 3 && j <= end5; j++)
                    matcher_insert_fast(m, src, j);
                for (int32_t j = pos + mlen - 3; j < pos + mlen && j <= end5; j++)
                    matcher_insert_fast(m, src, j);
            } else {
                /* Short match: insert all positions */
                int32_t end5 = end - 5;
                for (int32_t j = ins_first; j < pos + mlen && j <= end5; j++)
                    matcher_insert_fast(m, src, j);
            }

            update_rep(m, (uint32_t)moff);
            pos += mlen;
            lit_start = src + pos;
            failures = 0; /* matched: reset the no-match run */
            nmatch++;
        } else {
            if (!pos_inserted) matcher_insert(m, src, pos, end);
            /* Accel: skip ahead over unmatchable regions. accel==0 keeps
             * the byte-identical old default (advance 1). The skipped
             * positions are not hashed/inserted and simply become
             * literals. SPRINT 124: balanced/extreme cap the stride at 8
             * — on sparse-match data (struct-of-floats) an unbounded
             * ramp skips over match starts and costs double-digit ratio;
             * fast mode keeps the full lz4-style ramp. */
            if (m->accel) {
                uint32_t step = 1 + (((uint32_t)failures * m->accel) >> 6);
                if (mode >= VV_MODE_BALANCED && step > 8) step = 8;
                pos += (int32_t)step;
                failures++;
                /* Early RAW bail: 128 KB into the block with zero
                 * matches means this block is going raw anyway (csz
                 * would exceed braw). Returning 0 makes the caller
                 * emit a RAW block without paying for the rest of the
                 * parse or the literal memcpys. */
                if (nmatch == 0 && pos - (int32_t)start_pos >= (1 << 17))
                    return 0;
            } else {
                pos++;
            }
        }
    }

    /* ─── Trailing literals ─── */
    {
        size_t ll = (size_t)(src + end - lit_start);
        size_t needed = 1 + (ll >= 15 ? ll / 255 + 2 : 0) + ll;
        if ((size_t)(op - dst) + needed > dst_cap) return 0;
        op += emit_seq(op, lit_start, ll, 0, 0, off_bytes, min_match);
    }

    return (size_t)(op - dst);
}

/* ═══════════════════════════════════════════════════════════════
 * EXTRACT LITERALS FROM TOKEN STREAM
 *
 * Walks a type-1 LZ token stream, copies all literal bytes into
 * lit_buf and produces a "stripped" token stream (same format but
 * with literal bytes removed) in stripped_buf.
 *
 * Returns the number of literals extracted, or 0 on error.
 * ═══════════════════════════════════════════════════════════════ */

static size_t extract_literals(
    const uint8_t *tokens, size_t tok_len,
    uint8_t *lit_buf,      size_t lit_cap,
    uint8_t *stripped_buf,  size_t *stripped_len, int off_bytes)
{
    const uint8_t *tp = tokens;
    const uint8_t *tp_end = tokens + tok_len;
    uint8_t *sp = stripped_buf;
    size_t total_lits = 0;

    while (tp < tp_end) {
        uint8_t token = *tp++;
        *sp++ = token;  /* Copy token byte to stripped stream */

        size_t ll = token >> 4;
        size_t mc = token & 0x0F;

        /* Extended literal length */
        if (ll == 15) {
            size_t ext = 0;
            do {
                if (tp >= tp_end) return 0;
                uint8_t b = *tp++;
                *sp++ = b;  /* Copy extension byte */
                ext += b;
                if (b < 255) break;
            } while (tp < tp_end);
            ll += ext;
        }

        /* Literal bytes: copy to lit_buf, do NOT copy to stripped stream */
        if (tp + ll > tp_end) return 0;
        if (total_lits + ll > lit_cap) return 0;
        memcpy(lit_buf + total_lits, tp, ll);
        total_lits += ll;
        tp += ll;

        /* End of block: no more data = last sequence (no match) */
        if (tp >= tp_end) break;

        /* Offset: 2 or 3 bytes, copy to stripped stream */
        if (tp + off_bytes > tp_end) return 0;
        for (int i = 0; i < off_bytes; i++) *sp++ = *tp++;

        /* Extended match length */
        if (mc == 15) {
            size_t ext = 0;
            do {
                if (tp >= tp_end) return 0;
                uint8_t b = *tp++;
                *sp++ = b;
                ext += b;
                if (b < 255) break;
            } while (tp < tp_end);
            (void)ext;
        }
    }

    *stripped_len = (size_t)(sp - stripped_buf);
    return total_lits;
}

/* ═══════════════════════════════════════════════════════════════
 * BLOCK EMISSION HELPER
 *
 * Encodes a single block of up to VV_MAX_BLOCK_SIZE bytes from
 * src[block_start..block_start+braw) and emits the compressed block
 * to dst. Picks the best path (raw / LZ-raw / 'S' seq / 'I'/'C' lit)
 * via winner-takes-all in balanced+extreme modes.
 *
 * Used by both the one-shot vv_compress() and the streaming
 * vv_cstream_compress_chunk(). Expects:
 *   - src:          source buffer (full source for vv_compress; the
 *                   persistent stream buffer for streaming)
 *   - block_start:  offset in src where this block begins
 *   - braw:         block raw length (≤ VV_MAX_BLOCK_SIZE)
 *   - last:         1 if this is the last block in the frame
 *   - m:            matcher state (persists across blocks)
 *   - mode:         compression mode (affects path choice)
 *   - wlog:         window log
 *   - tmp/tcap:     scratch buffer for LZ-compressed tokens
 *   - lit_buf/lit_cap, stripped, ent_buf/ent_cap: entropy scratch
 *   - dst/dst_cap:  output buffer
 *
 * Returns bytes written to dst on success, or 0 on overflow. */
/* SPRINT 124: high-watermark tracking for the secure-zero scrub.
 * Scrubbing full buffer capacities (~4 MB) per vv_compress call cost
 * up to 14% of encode wall on fast inputs; only bytes actually written
 * can hold plaintext, so tracking write watermarks preserves the
 * Sprint 117 security property at a fraction of the cost. */
typedef struct {
    size_t tmp, lit, stripped, ent_front, ent_back;
} scrub_wm_t;

static inline void wm_max(size_t *wm, size_t used) {
    if (used > *wm) *wm = used;
}

static size_t emit_block(const uint8_t *src, size_t block_start, size_t braw,
                         int last, matcher_t *m, vv_mode_t mode, uint8_t wlog,
                         uint8_t *tmp, size_t tcap,
                         uint8_t *lit_buf, size_t lit_cap,
                         uint8_t *stripped, uint8_t *ent_buf, size_t ent_cap,
                         uint8_t *dst, size_t dst_cap, int min_match,
                         int compat_v246_5, scrub_wm_t *wm) {
    uint8_t *op = dst;

    /* SPRINT 42/43 RATIO PROGRAM: extreme mode uses the whole-block optimal
     * parser; balanced/fast keep greedy/lazy. csz==0 (overflow/alloc) flows
     * into the raw-store branch below.
     *
     * SPRINT 124: on format-v2 (binary-detected) input, extreme uses the
     * deep greedy/lazy parser instead. The optimal DP prices every match
     * at full log2(offset) cost — it has no rep-offset model — so on
     * rep-heavy record data (struct-of-floats, sensor logs) it loses
     * 15-20% ratio to the rep-aware greedy path, and on incompressible
     * binary it pays a full O(N·depth) DP just to store raw (the greedy
     * path has skip acceleration and an early-RAW bail). Text-like input
     * keeps the optimal parser, where it wins 3-11% over greedy. */
    size_t csz;
    int v2_block = (min_match < (int)VV_MIN_MATCH);
    if (mode >= VV_MODE_EXTREME && !v2_block)
        csz = compress_block_optimal(src, block_start, braw, tmp, tcap, m, min_match);
    else
        csz = compress_block(src, block_start, braw, tmp, tcap, m, mode, min_match);
    if (wm) wm_max(&wm->tmp, csz);

    /* SPRINT 124: in balanced/extreme, a token stream slightly larger
     * than raw can still win AFTER entropy coding — on low-match data
     * (struct-of-floats, sensor logs) nearly all the compression comes
     * from the entropy stage over literals, not from matches. Only the
     * entropy-less fast path must reject csz >= braw outright. */
    size_t raw_gate = (mode >= VV_MODE_BALANCED) ? braw + braw / 8 : braw;
    if (csz == 0 || csz >= raw_gate) {
        /* Incompressible: store raw */
        if ((size_t)(op - dst) + 4 + braw > dst_cap) return 0;
        uint32_t bh = vv_bh_pack(VV_BLOCK_RAW, last, (uint32_t)braw);
        memcpy(op, &bh, 4); op += 4;
        memcpy(op, src + block_start, braw); op += braw;
        return (size_t)(op - dst);
    }

    if (mode >= VV_MODE_BALANCED) {
        /* Path A: sequence coding ('S') */
        size_t seq_len = 0;
        int seq_valid = 0;
        size_t seq_block_sz = (size_t)-1;
        int off_bytes = (wlog > 16) ? 3 : 2;
        /* Format v2: when min_match < 4 (i.e. 3), encode with the v2
         * table so length-3 matches are representable as code 0. The
         * token stream produced by compress_block(min_match=3) may
         * contain 3-byte matches that v1 encode_sequences cannot
         * represent correctly. */
        int use_v2 = (min_match < (int)VV_MIN_MATCH);
        /* Sprint 105 Phase C: thread compat flag through to SEQ encoder. */
        int dis_huf4 = compat_v246_5;
        vva_error_t serr = use_v2
            ? vva_encode_sequences_v2_compat(tmp, csz, ent_buf, ent_cap, &seq_len, off_bytes, dis_huf4)
            : vva_encode_sequences_compat(tmp, csz, ent_buf, ent_cap, &seq_len, off_bytes, dis_huf4);
        if (serr == VVA_OK) {
            seq_block_sz = 4 + 3 + 1 + seq_len;
            seq_valid = 1;
        }
        if (wm) wm_max(&wm->ent_front, seq_len);

        /* Path B: literal-only entropy ('I' or 'A') */
        size_t stripped_len = 0;
        size_t lit_count = 0;
        uint8_t *ent_buf2 = ent_buf + ent_cap / 2;
        size_t ent_cap2 = ent_cap / 2;
        size_t ent_len = 0;
        uint8_t ent_tag = 0;
        size_t ent_block_sz = (size_t)-1;

        /* Path B gate (v2.53.3, revised SPRINT 124): Path B has a
         * measured 0% win rate against Path A (SEQ) on real inputs —
         * SEQ codes the same literals at least as small while also
         * coding the matches. Run it only when SEQ failed or produced
         * weak output (>= 7/8 of raw). Path B is v1-only (its stripped
         * tokens carry v1 matchlen bias), so on the v2 path skip the
         * work entirely — the result could never be emitted.
         *
         * SPRINT 124: the CTX (order-1) coder is gone from this path.
         * It ran exactly when SEQ was weak — low-redundancy binary —
         * where it burned 50% of encode wall (sensors-class inputs)
         * and, per the Sprint 53 measurements, never won a block. */
        int try_path_b = !use_v2 && (!seq_valid ||
                                     seq_block_sz >= (braw * 7 / 8));

        if (try_path_b) {
            lit_count = extract_literals(tmp, csz, lit_buf, lit_cap,
                                         stripped, &stripped_len, off_bytes);
            if (wm) {
                wm_max(&wm->lit, lit_count);
                wm_max(&wm->stripped, stripped_len);
            }
            if (lit_count > 0) {
                vva_error_t aerr = vva_encode4(lit_buf, lit_count,
                                                ent_buf2, ent_cap2, &ent_len);
                if (aerr == VVA_OK) ent_tag = VV_ENTROPY_ANS4;
                if (!ent_tag) {
                    aerr = vva_encode(lit_buf, lit_count,
                                      ent_buf2, ent_cap2, &ent_len);
                    if (aerr == VVA_OK) ent_tag = VV_ENTROPY_ANS;
                }
                if (ent_tag) {
                    ent_block_sz = 4 + 3 + 1 + 2 + 2 + ent_len + stripped_len;
                }
                if (wm) wm_max(&wm->ent_back, ent_len);
            }
        }

        size_t raw_block_sz = 4 + 3 + csz;
        /* Raw-store block size: with the relaxed raw_gate above, csz may
         * exceed braw, so every candidate must also beat plain storage. */
        size_t store_sz = 4 + braw;
        if (raw_block_sz > store_sz) raw_block_sz = store_sz;

        if (seq_valid && seq_block_sz <= ent_block_sz && seq_block_sz < raw_block_sz) {
            if ((size_t)(op - dst) + seq_block_sz > dst_cap) return 0;
            uint32_t bh = vv_bh_pack(VV_BLOCK_ENTROPY, last, (uint32_t)braw);
            memcpy(op, &bh, 4); op += 4;
            uint32_t total_comp = (uint32_t)(1 + seq_len);
            op[0] = (uint8_t)(total_comp);
            op[1] = (uint8_t)(total_comp >> 8);
            op[2] = (uint8_t)(total_comp >> 16);
            op += 3;
            *op++ = use_v2 ? VV_ENTROPY_SEQ_V2 : VV_ENTROPY_SEQ;
            memcpy(op, ent_buf, seq_len); op += seq_len;
        } else if (!use_v2 && ent_tag && ent_block_sz < raw_block_sz) {
            /* Path B (H/I/C entropy) uses `stripped` tokens which still
             * contain v1-format matchlen bytes. Only safe for v1. For
             * v2, we must skip this fallback to avoid emitting v1 tokens
             * that a v2-aware decoder wouldn't reconstruct correctly. */
            if ((size_t)(op - dst) + ent_block_sz > dst_cap) return 0;
            uint32_t bh = vv_bh_pack(VV_BLOCK_ENTROPY, last, (uint32_t)braw);
            memcpy(op, &bh, 4); op += 4;
            uint32_t total_comp = (uint32_t)(5 + ent_len + stripped_len);
            op[0] = (uint8_t)(total_comp);
            op[1] = (uint8_t)(total_comp >> 8);
            op[2] = (uint8_t)(total_comp >> 16);
            op += 3;
            *op++ = ent_tag;
            op[0] = (uint8_t)(lit_count); op[1] = (uint8_t)(lit_count >> 8); op += 2;
            op[0] = (uint8_t)(ent_len); op[1] = (uint8_t)(ent_len >> 8); op += 2;
            memcpy(op, ent_buf2, ent_len); op += ent_len;
            memcpy(op, stripped, stripped_len); op += stripped_len;
        } else if (!use_v2 && csz < braw) {
            /* Plain VV_BLOCK_COMPRESSED carries raw v1-format tokens.
             * For v2, we must not emit these — the decoder would
             * reconstruct matchlen with +4 instead of +3. Guarded on
             * csz < braw because the relaxed raw_gate can let a token
             * stream slightly larger than raw reach this point. */
            if ((size_t)(op - dst) + 4 + 3 + csz > dst_cap) return 0;
            uint32_t bh = vv_bh_pack(VV_BLOCK_COMPRESSED, last, (uint32_t)braw);
            memcpy(op, &bh, 4); op += 4;
            op[0] = (uint8_t)(csz); op[1] = (uint8_t)(csz >> 8); op[2] = (uint8_t)(csz >> 16);
            op += 3;
            memcpy(op, tmp, csz); op += csz;
        } else {
            /* Nothing beat plain storage: emit RAW. */
            if ((size_t)(op - dst) + 4 + braw > dst_cap) return 0;
            uint32_t bh = vv_bh_pack(VV_BLOCK_RAW, last, (uint32_t)braw);
            memcpy(op, &bh, 4); op += 4;
            memcpy(op, src + block_start, braw); op += braw;
        }
    } else {
        /* Ultra-fast mode */
        if ((size_t)(op - dst) + 4 + 3 + csz > dst_cap) return 0;
        uint32_t bh = vv_bh_pack(VV_BLOCK_COMPRESSED, last, (uint32_t)braw);
        memcpy(op, &bh, 4); op += 4;
        op[0] = (uint8_t)(csz); op[1] = (uint8_t)(csz >> 8); op[2] = (uint8_t)(csz >> 16);
        op += 3;
        memcpy(op, tmp, csz); op += csz;
    }

    return (size_t)(op - dst);
}

/* ═══════════════════════════════════════════════════════════════
 * PUBLIC API: COMPRESS
 * ═══════════════════════════════════════════════════════════════ */

size_t vv_compress_bound(size_t src_len) {
    return src_len + src_len / 255 + 256
         + sizeof(vv_frame_header_t) + sizeof(vv_frame_footer_t);
}

/* Public vv_compress: select and apply a reversible BCJ branch filter, then
 * compress. A filter may be requested explicitly (filter_x86 / filter_arm64)
 * or chosen automatically (filter_auto: sniff the executable header). The
 * filter runs on a private copy because the public input is const; the
 * matching header flag (bit2 x86 / bit3 ARM64), set by vv_compress_inner from
 * the resolved options, tells the decoder to invert it. When no filter
 * applies, this is a direct pass-through with no copy and byte-identical
 * output. */
int64_t vv_compress_inner(const uint8_t *src, size_t src_len,
                          uint8_t *dst, size_t dst_cap,
                          const vv_options_t *opts);

int64_t vv_compress(const uint8_t *src, size_t src_len,
                    uint8_t *dst, size_t dst_cap,
                    const vv_options_t *opts) {
    int auto_on = opts && opts->filter_auto &&
                  !opts->filter_x86 && !opts->filter_arm64;

    if (opts && (opts->filter_x86 || opts->filter_arm64 || auto_on) &&
        src_len > 0 && src) {
        vv_options_t eff = *opts;
        if (auto_on) {
            vv_filter_kind_t k = vv_bcj_detect(src, src_len);
            if (k == VV_FILTER_X86)        eff.filter_x86 = 1;
            else if (k == VV_FILTER_ARM64) eff.filter_arm64 = 1;
            /* k == NONE: leave eff with no filter -> falls through below */
        }
        if (eff.filter_x86 || eff.filter_arm64) {
            uint8_t *copy = (uint8_t *)malloc(src_len);
            if (!copy) return VV_ERR_NOMEM;
            memcpy(copy, src, src_len);
            if (eff.filter_x86)
                vv_bcj_x86(copy, src_len, 0, 1);     /* forward: relative -> absolute */
            else
                vv_bcj_arm64(copy, src_len, 0, 1);   /* AArch64 BL + ADRP */
            int64_t r = vv_compress_inner(copy, src_len, dst, dst_cap, &eff);
            free(copy);
            return r;
        }
        /* auto-detect found no executable header: fall through unchanged */
    }
    return vv_compress_inner(src, src_len, dst, dst_cap, opts);
}

int64_t vv_compress_inner(const uint8_t *src, size_t src_len,
                    uint8_t *dst, size_t dst_cap,
                    const vv_options_t *opts) {
    /* SPRINT 95 audit: accept NULL opts (fall back to defaults) for
     * consistency with vv_cstream_create. Also accept src_len=0
     * (an empty frame is a valid thing to produce — some streaming
     * protocols rely on it as a flush marker). */
    if (!dst) return VV_ERR_PARAM;
    if (src_len > 0 && !src) return VV_ERR_PARAM;
    if (dst_cap < sizeof(vv_frame_header_t) + sizeof(vv_frame_footer_t) + 16)
        return VV_ERR_OVERFLOW;

    vv_options_t local_opts;
    if (!opts) {
        vv_default_options(&local_opts);
        opts = &local_opts;
    }

    uint8_t wlog = opts->window_log;
    uint32_t depth;
    if (wlog == 0) {
        switch (opts->mode) {
        case VV_MODE_ULTRA_FAST: wlog = 16; break;
        case VV_MODE_BALANCED:   wlog = 16; break; /* may be overridden below */
        case VV_MODE_EXTREME:    wlog = 16; break; /* may be overridden below */
        }
    }
    switch (opts->mode) {
    case VV_MODE_ULTRA_FAST: depth = 4; break;
    case VV_MODE_BALANCED:   depth = 24; break; /* was 48 — halving barely affects ratio, doubles speed */
    case VV_MODE_EXTREME:    depth = 256; break;
    default: depth = 24;
    }
    /* Opt-in chain-depth override (default 0 = mode default, byte-identical). */
    if (opts->depth_override) {
        depth = opts->depth_override;
        if (depth > 4096) depth = 4096;
    }

    /* ─── ADAPTIVE WINDOW + HASH4 detection in a single trial.
     * PERF: previously this was two separate 128K+64K=192K trials, run
     * sequentially. We can make BOTH decisions from the SAME trial:
     *   - window: wlog=20 wins if it saves ≥3% vs wlog=16
     *   - hash4:  enable if ratio < 2:1 (indicates binary-like data) */
    int enable_hash4 = 0;
    if (opts->window_log == 0 && opts->mode >= VV_MODE_BALANCED && src_len > 65536) {
        size_t trial_len = 131072;
        if (trial_len > src_len) trial_len = src_len;

        size_t trial_cap = trial_len + trial_len / 255 + 1024;
        uint8_t *trial_buf = (uint8_t *)malloc(trial_cap);
        if (trial_buf) {
            matcher_t m16;
            size_t sz16 = 0, sz20 = 0;
            /* SPRINT 93 audit: matcher_init can fail; if it does, skip
             * the trial (this path is a perf-tuning probe — falling
             * back to default wlog is safe).
             * SPRINT 124: trials run with accel=2 so incompressible
             * inputs no longer pay two full 128 KB parses just to
             * decide "store raw". Both trials use the same accel, so
             * the 16-vs-20 comparison stays apples-to-apples. */
            if (matcher_init(&m16, 16, 4)) {
                m16.accel = 2;
                sz16 = compress_block(src, 0, trial_len, trial_buf, trial_cap, &m16, VV_MODE_ULTRA_FAST, VV_MIN_MATCH);
                matcher_free(&m16);
            }

            matcher_t m20;
            if (matcher_init(&m20, 20, 4)) {
                m20.accel = 2;
                sz20 = compress_block(src, 0, trial_len, trial_buf, trial_cap, &m20, VV_MODE_ULTRA_FAST, VV_MIN_MATCH);
                matcher_free(&m20);
            }

            free(trial_buf);
            if (sz20 > 0 && sz16 > 0 && sz20 < (sz16 * 97 / 100)) wlog = 20;
            /* Binary-like detection: best trial ratio < 2:1. A zero
             * size means the early-RAW bail fired — maximally
             * incompressible, so binary-like by definition. */
            size_t best_sz = (sz20 > 0 && sz20 < sz16) ? sz20 : sz16;
            if (best_sz == 0 || best_sz * 2 > trial_len) enable_hash4 = 1;
        }
    }

    /* SPRINT 124: adaptive format v2 (decided here because the window
     * overrides below must not fire for v2-routed input). min_match=3
     * ('T' blocks) is a measured 14%+ ratio win on struct-of-floats/
     * record binary and 2-3% on ELF, while slightly HURTING text/JSON
     * ratio and decode speed (more, shorter sequences). Auto-enable
     * exactly where it wins: binary-detected inputs. Suppressed by
     * the compat flag because 'T' blocks require a v2.33.0+ decoder.
     * Explicit opts->format_v2 still forces it for any input. */
    int use_v2_fmt = opts->format_v2 ||
                     (enable_hash4 && opts->mode >= VV_MODE_BALANCED &&
                      !opts->compat_v246_5_decoder);

    /* SPRINT 67: size-based wlog override. The trial above often
     * misses wins that only become visible past the 128 KB trial
     * boundary (long-range refs in multi-MB files). Override to
     * wlog=18 for files ≥ 3 MB when the trial left wlog at 16.
     * SPRINT 124: not for v2-routed (binary) input — the greedy
     * parser regresses badly on rep-heavy data with large windows
     * (diverse far offsets break rep streaks and bloat OF codes). */
    if (opts->window_log == 0 && opts->mode >= VV_MODE_BALANCED &&
        !use_v2_fmt && wlog == 16 && src_len >= 3145728) {
        wlog = 18;
    }

    /* SPRINT 46 (RATIO PROGRAM): extreme-mode large-window scaling.
     * The trial/override above caps extreme at wlog≈18-20 (256KB-1MB),
     * far too small for the multi-MB Silesia fixtures with long-range
     * structure (nci 33MB, webster 41MB, mozilla 51MB). The whole-block
     * optimal parser exploits a larger window across block boundaries
     * (the matcher chains persist between blocks).
     *
     * Scale wlog with file size, capped at 2^24 = 16 MB. The cap is a
     * HARD wire-format limit: the offset field is 3 bytes (24 bits) for
     * wlog>16, so the maximum representable offset is exactly 2^24.
     * (Reaching 2^27 like zstd --long requires 4-byte offsets — a
     * wire-format change deferred to Lever B.)
     *
     * REQUIRED companion fix (same sprint): the ANS sequence decoder's
     * SAFEZONE_MAX_OFFSET was raised from 1<<20 to 1<<24, since it
     * previously rejected any offset > 1 MB as corrupt. Without that
     * fix this scaling breaks roundtrip on multi-block files (the bug
     * diagnosed and reverted in Sprint 45).
     *
     * Memory at wlog=24: chain[wsz]+hash4_chain[wsz] = 2*4*16M = 128 MB
     * matcher. Acceptable for extreme ("max ratio, will wait"). */
    if (opts->window_log == 0 && opts->mode >= VV_MODE_EXTREME &&
        !use_v2_fmt && src_len > (1u << 20)) {
        /* SPRINT 124: v2-routed (binary) extreme input uses the greedy
         * parser (no rep model in the optimal DP), and greedy + large
         * window is a measured 15-30% ratio LOSS on rep-heavy data —
         * keep the trial-chosen window there. */
        uint8_t want = 20;
        uint64_t s = src_len;
        while ((1ull << want) < s && want < 24) want++;
        if (want > wlog) wlog = want;
    }


    /* Frame header */
    uint8_t *op = dst;
    vv_frame_header_t fh;
    memset(&fh, 0, sizeof(fh));
    fh.magic = VV_MAGIC;
    fh.version = 1;
    fh.flags = (opts->checksum ? 1 : 0)
             | (opts->filter_x86 ? 4 : 0)
             | (opts->filter_arm64 ? 8 : 0);
    fh.mode_hint = (uint8_t)opts->mode;
    fh.window_log = wlog;
    fh.content_size = (uint64_t)src_len;
    memcpy(op, &fh, sizeof(fh)); op += sizeof(fh);

    /* Matcher */
    matcher_t m;
    /* SPRINT 93 audit: handle allocation failure cleanly */
    if (!matcher_init(&m, wlog, depth)) {
        return VV_ERR_NOMEM;
    }
    m.use_hash4 = (uint8_t)enable_hash4; /* From fused adaptive-window trial */
    /* SPRINT 58: enable the single-probe match finder for ULTRA_FAST.
     * Set here (not in matcher_init) so the depth-4 chain matchers used
     * by the balanced/extreme window-selection trial above stay at
     * single_probe==0 and produce bit-identical trial sizes. */
    m.single_probe = (opts->mode == VV_MODE_ULTRA_FAST) ? 1 : 0;
    /* SPRINT 124: accel defaults ON. opts->accel == 0 now means "auto":
     * fast mode gets the lz4-style ramp (2 → step 1 + failures/32),
     * balanced/extreme a gentle one (1 → step 1 + failures/64, capped
     * at 8 inside compress_block). This is what turns 1 MB of random
     * bytes from a 24 ns/byte full-parse crawl into a near-memcpy RAW
     * store. Explicit --accel values are honored unchanged. */
    {
        uint32_t eff_accel = opts->accel;
        if (eff_accel == 0)
            eff_accel = (opts->mode >= VV_MODE_BALANCED) ? 1 : 2;
        m.accel = eff_accel > 64 ? 64 : eff_accel;
    }
    m.no_rep = opts->no_rep ? 1 : 0;
    /* Format v2 cap applies to EVERY match emitted from this matcher,
     * not just those produced via hash3. Set unconditionally when
     * the v2 format is active. */
    if (use_v2_fmt) {
        matcher_set_format_v2(&m);
    }
    /* Hash3 enablement is a separate, adaptive decision. Only fires
     * on binary-like data (enable_hash4) where length-3 matches
     * actually help. On text/JSON it stays off to avoid regressions. */
    if (use_v2_fmt && enable_hash4) {
        if (!matcher_enable_hash3(&m)) {
            matcher_free(&m);
            return VV_ERR_NOMEM;
        }
    }

    /* Temp buffer.
     * PERF: size to the actual input (not always 1MB). For a 4KB input,
     * tcap was ~1.03MB — a wasteful allocation. Now allocate just enough
     * to hold the LZ-tokenized output, bounded by VV_MAX_BLOCK_SIZE. */
    size_t block_bound = src_len < VV_MAX_BLOCK_SIZE ? src_len : VV_MAX_BLOCK_SIZE;
    size_t tcap = block_bound + block_bound / 255 + 1024;
    uint8_t *tmp = (uint8_t *)malloc(tcap);
    if (!tmp) { matcher_free(&m); return VV_ERR_NOMEM; }

    /* Additional buffers for entropy path (only allocated if needed) */
    uint8_t *lit_buf = NULL, *stripped = NULL, *ent_buf = NULL;
    size_t lit_cap = 0, ent_cap = 0;
    if (opts->mode >= VV_MODE_BALANCED) {
        /* PERF: size these to the actual input too — they only need to
         * cover the single in-flight block's worth of literals/entropy
         * output. For small one-shot calls this avoids ~3 MB of wasted
         * allocation and page-faulting every call. */
        lit_cap = block_bound;
        /* SPRINT 124 (latent-corruption fix): ent_buf is shared by Path A
         * (SEQ, writes at ent_buf[0..]) and Path B (literal entropy,
         * writes at ent_buf + ent_cap/2). SEQ output on weak blocks can
         * reach vva_bound(braw) — with ent_cap == vva_bound the halves
         * OVERLAP and Path B silently clobbers SEQ's tail before the
         * winner is chosen. Size the buffer so each half holds a full
         * vva_bound worth of output. */
        ent_cap = 2 * vva_bound(block_bound);
        lit_buf = (uint8_t *)malloc(lit_cap);
        stripped = (uint8_t *)malloc(tcap);
        ent_buf = (uint8_t *)malloc(ent_cap);
        if (!lit_buf || !stripped || !ent_buf) {
            free(lit_buf); free(stripped); free(ent_buf);
            free(tmp); matcher_free(&m);
            return VV_ERR_NOMEM;
        }
    }

    size_t remaining = src_len;
    const uint8_t *ip = src;

    if (remaining == 0) {
        uint32_t bh = vv_bh_pack(VV_BLOCK_RAW, 1, 0);
        memcpy(op, &bh, 4); op += 4;
    }

    /* Format v2 (explicit or adaptive): encode with min_match=3.
     * Produces 'T'-tagged ENTROPY blocks which only v2.33.0+ decoders
     * can read. Closes the real-binary compression gap vs gzip-9. */
    int min_match = use_v2_fmt ? 3 : (int)VV_MIN_MATCH;

    scrub_wm_t wm = {0, 0, 0, 0, 0};

    while (remaining > 0) {
        size_t braw = remaining > VV_MAX_BLOCK_SIZE ? VV_MAX_BLOCK_SIZE : remaining;
        int last = (remaining <= VV_MAX_BLOCK_SIZE);

        size_t block_start = (size_t)(ip - src);
        size_t written = emit_block(src, block_start, braw, last, &m, opts->mode, wlog,
                                    tmp, tcap, lit_buf, lit_cap,
                                    stripped, ent_buf, ent_cap,
                                    op, dst_cap - (size_t)(op - dst), min_match,
                                    opts->compat_v246_5_decoder, &wm);
        if (written == 0) {
            free(lit_buf); free(stripped); free(ent_buf);
            free(tmp); matcher_free(&m);
            return VV_ERR_OVERFLOW;
        }
        op += written;
        ip += braw; remaining -= braw;
    }

    /* Sprint 117: scrub plaintext-derived working buffers before free
     * to prevent heap-residue leak (defense in depth).
     * SPRINT 124: scrub only up to each buffer's write watermark —
     * bytes beyond it were never written and cannot hold plaintext. */
    vv_secure_zero(tmp, wm.tmp < tcap ? wm.tmp : tcap);
    if (lit_buf)  vv_secure_zero(lit_buf, wm.lit < lit_cap ? wm.lit : lit_cap);
    if (stripped) vv_secure_zero(stripped, wm.stripped < tcap ? wm.stripped : tcap);
    if (ent_buf) {
        vv_secure_zero(ent_buf, wm.ent_front < ent_cap ? wm.ent_front : ent_cap);
        size_t back_cap = ent_cap - ent_cap / 2;
        if (wm.ent_back)
            vv_secure_zero(ent_buf + ent_cap / 2,
                           wm.ent_back < back_cap ? wm.ent_back : back_cap);
    }
    free(lit_buf); free(stripped); free(ent_buf);
    free(tmp);

    if (opts->checksum) {
        vv_frame_footer_t ff;
        ff.checksum = vv_xxh64(src, src_len, 0);
        ff.footer_magic = 0x56564E44u;
        memcpy(op, &ff, sizeof(ff)); op += sizeof(ff);
    }

    matcher_free(&m);
    return (int64_t)(op - dst);
}

/* ═══════════════════════════════════════════════════════════════
 * STREAMING COMPRESSION
 *
 * A compression stream buffers persistent state across calls:
 *   - The matcher (hash tables, chains, rep-match offsets)
 *   - Scratch buffers (tmp/lit_buf/stripped/ent_buf)
 *   - Streaming xxh64 state for the frame checksum
 *   - The full input so far in sliding-window form (needed because
 *     LZ matches can reference up to 2^wlog bytes back)
 *
 * Each call to vv_cstream_compress_chunk() appends chunk bytes to
 * the internal source buffer, emits one block covering those bytes,
 * and optionally emits the frame header (first call) and footer
 * (when is_last is set).
 *
 * Memory cost: 2 × window_size + ~10 MB scratch (ent_buf, etc.).
 * For wlog=16 that's ~131 KB + scratch; wlog=20 is ~2 MB + scratch.
 * ═══════════════════════════════════════════════════════════════ */

struct vv_cstream_s {
    vv_options_t opts;
    uint8_t       wlog;
    matcher_t     m;

    /* Scratch buffers — allocated once, reused across chunks */
    uint8_t *tmp;       size_t tcap;
    uint8_t *lit_buf;   size_t lit_cap;
    uint8_t *stripped;
    uint8_t *ent_buf;   size_t ent_cap;

    /* Sliding-window source buffer. We accumulate input so offset-based
     * match references resolve correctly. Old bytes beyond the window
     * are dropped in periodic compaction. */
    uint8_t *src_buf;        /* Capacity = 2 × window_size */
    size_t   src_cap;
    size_t   src_head;       /* First valid byte index in src_buf */
    size_t   src_len;        /* Number of valid bytes in src_buf */
    size_t   global_offset;  /* src_buf[i] corresponds to stream offset (global_offset - src_len + i) */

    /* Streaming checksum */
    vv_xxh64_state_t cks;

    int header_emitted;
};

vv_cstream_t *vv_cstream_create(const vv_options_t *opts) {
    vv_cstream_t *ctx = (vv_cstream_t *)calloc(1, sizeof(vv_cstream_t));
    if (!ctx) return NULL;

    if (opts) ctx->opts = *opts;
    else vv_default_options(&ctx->opts);

    /* Resolve window log (fixed for streams — no adaptive probe) */
    uint8_t wlog = ctx->opts.window_log;
    if (wlog == 0) wlog = 16;
    ctx->wlog = wlog;

    uint32_t depth;
    switch (ctx->opts.mode) {
    case VV_MODE_ULTRA_FAST: depth = 4; break;
    case VV_MODE_BALANCED:   depth = 24; break;
    case VV_MODE_EXTREME:    depth = 256; break;
    default: depth = 24;
    }
    if (ctx->opts.depth_override) {
        depth = ctx->opts.depth_override;
        if (depth > 4096) depth = 4096;
    }

    /* SPRINT 93 audit: matcher_init can fail; cstream returns NULL
     * on any allocation error per public API contract. */
    if (!matcher_init(&ctx->m, wlog, depth)) {
        free(ctx);
        return NULL;
    }
    /* SPRINT 58: single-probe finder for ULTRA_FAST streaming, matching
     * the one-shot fast path. balanced/extreme keep single_probe==0. */
    ctx->m.single_probe = (ctx->opts.mode == VV_MODE_ULTRA_FAST) ? 1 : 0;
    ctx->m.accel = ctx->opts.accel > 64 ? 64 : ctx->opts.accel;
    ctx->m.no_rep = ctx->opts.no_rep ? 1 : 0;
    /* Format v2 matchlen cap applies to every match — set whenever
     * streaming opts has format_v2 on, not just when hash3 fires.
     *
     * Sprint 89 audit: read from ctx->opts (populated above with either
     * the caller's opts or default values) rather than the raw opts
     * pointer, which can be NULL when caller wants defaults. The prior
     * code dereferenced NULL when called as vv_cstream_create(NULL). */
    if (ctx->opts.format_v2) {
        matcher_set_format_v2(&ctx->m);
    }
    /* SPRINT 45: enable hash3 for format v2 streaming. Must free
     * ctx before returning NULL — callers use NULL-check semantics
     * here, not error codes. */
    if (ctx->opts.format_v2) {
        if (!matcher_enable_hash3(&ctx->m)) {
            matcher_free(&ctx->m);
            free(ctx);
            return NULL;
        }
    }

    /* Scratch buffers sized for VV_MAX_BLOCK_SIZE */
    ctx->tcap    = VV_MAX_BLOCK_SIZE + VV_MAX_BLOCK_SIZE / 255 + 1024;
    ctx->tmp     = (uint8_t *)malloc(ctx->tcap);
    ctx->lit_cap = VV_MAX_BLOCK_SIZE;
    ctx->lit_buf = (uint8_t *)malloc(ctx->lit_cap);
    /* SPRINT 124: stripped tokens can slightly exceed the raw block
     * size now that emit_block lets csz ∈ [braw, braw*9/8) reach the
     * entropy stage — size like tmp, not like lit_buf. */
    ctx->stripped = (uint8_t *)malloc(ctx->tcap);
    /* SPRINT 124: 2× so Path A (front half) and Path B (back half)
     * can never overlap — see the matching fix in vv_compress_inner. */
    ctx->ent_cap = 2 * vva_bound(VV_MAX_BLOCK_SIZE);
    ctx->ent_buf = (uint8_t *)malloc(ctx->ent_cap);

    /* Source window = 2 × window_size so a full block of input can
     * land before we compact. */
    size_t window = (size_t)1u << wlog;
    ctx->src_cap = window * 2 + VV_MAX_BLOCK_SIZE;
    ctx->src_buf = (uint8_t *)malloc(ctx->src_cap);

    if (!ctx->tmp || !ctx->lit_buf || !ctx->stripped || !ctx->ent_buf || !ctx->src_buf) {
        vv_cstream_destroy(ctx);
        return NULL;
    }

    if (ctx->opts.checksum) vv_xxh64_init(&ctx->cks, 0);
    ctx->header_emitted = 0;
    return ctx;
}

void vv_cstream_destroy(vv_cstream_t *ctx) {
    if (!ctx) return;
    /* Sprint 117: zero plaintext-derived working buffers before free.
     * lit_buf and stripped contain literal bytes from the input; src_buf
     * holds raw input. tmp/ent_buf may contain compressed-but-not-yet-
     * encrypted output. All are scrubbed to prevent heap-residue leak. */
    if (ctx->tmp)      vv_secure_zero(ctx->tmp, ctx->tcap);
    if (ctx->lit_buf)  vv_secure_zero(ctx->lit_buf, ctx->lit_cap);
    if (ctx->stripped) vv_secure_zero(ctx->stripped, ctx->tcap);
    if (ctx->ent_buf)  vv_secure_zero(ctx->ent_buf, ctx->ent_cap);
    if (ctx->src_buf)  vv_secure_zero(ctx->src_buf, ctx->src_cap);
    free(ctx->tmp); free(ctx->lit_buf); free(ctx->stripped); free(ctx->ent_buf);
    free(ctx->src_buf);
    matcher_free(&ctx->m);
    /* Scrub the context itself in case it held sensitive options */
    vv_secure_zero(ctx, sizeof(*ctx));
    free(ctx);
}

int vv_cstream_reset(vv_cstream_t *ctx, const vv_options_t *opts) {
    if (!ctx) return VV_ERR_PARAM;

    /* Apply new options if provided. window_log cannot change without
     * reallocating the matcher tables — reject the change. */
    if (opts) {
        uint8_t new_wlog = opts->window_log;
        if (new_wlog == 0) new_wlog = 16;
        if (new_wlog != ctx->wlog) return VV_ERR_PARAM;
        ctx->opts = *opts;
    }

    /* Update chain_depth in case the mode changed */
    uint32_t depth;
    switch (ctx->opts.mode) {
    case VV_MODE_ULTRA_FAST: depth = 4; break;
    case VV_MODE_BALANCED:   depth = 24; break;
    case VV_MODE_EXTREME:    depth = 256; break;
    default: depth = 24;
    }
    if (ctx->opts.depth_override) {
        depth = ctx->opts.depth_override;
        if (depth > 4096) depth = 4096;
    }
    ctx->m.chain_depth = depth;
    /* SPRINT 58: keep the single-probe flag in sync if the mode changed
     * across reset (e.g. balanced stream reset to fast). */
    ctx->m.single_probe = (ctx->opts.mode == VV_MODE_ULTRA_FAST) ? 1 : 0;
    ctx->m.accel = ctx->opts.accel > 64 ? 64 : ctx->opts.accel;
    ctx->m.no_rep = ctx->opts.no_rep ? 1 : 0;

    matcher_reset(&ctx->m);

    /* Reset sliding-window source buffer */
    ctx->src_head = 0;
    ctx->src_len = 0;
    ctx->global_offset = 0;

    /* Reset checksum */
    if (ctx->opts.checksum) vv_xxh64_init(&ctx->cks, 0);

    ctx->header_emitted = 0;
    return VV_OK;
}

int vv_cstream_compress_chunk(vv_cstream_t *ctx,
                              const uint8_t *chunk, size_t chunk_len,
                              uint8_t *dst, size_t dst_cap,
                              size_t *written, int is_last) {
    if (!ctx || !dst || !written) return VV_ERR_PARAM;
    if (chunk_len > VV_MAX_BLOCK_SIZE) return VV_ERR_PARAM;
    *written = 0;

    uint8_t *op = dst;
    size_t cap_left = dst_cap;

    /* Emit frame header on first call */
    if (!ctx->header_emitted) {
        if (cap_left < sizeof(vv_frame_header_t)) return VV_ERR_OVERFLOW;
        vv_frame_header_t fh;
        memset(&fh, 0, sizeof(fh));
        fh.magic = VV_MAGIC;
        fh.version = 1;
        fh.flags = ctx->opts.checksum ? 1 : 0;
        fh.mode_hint = (uint8_t)ctx->opts.mode;
        fh.window_log = ctx->wlog;
        /* content_size unknown in streaming mode → 0 */
        fh.content_size = 0;
        memcpy(op, &fh, sizeof(fh));
        op += sizeof(fh); cap_left -= sizeof(fh);
        ctx->header_emitted = 1;
    }

    /* Append chunk to sliding-window source buffer.
     * Compact the buffer if needed to stay under src_cap. We keep
     * the last (window_size) bytes as match-lookback history. */
    if (chunk_len > 0) {
        size_t window = (size_t)1u << ctx->wlog;
        size_t needed = ctx->src_len + chunk_len;
        if (needed > ctx->src_cap) {
            /* Compact: drop everything older than (window) bytes before end */
            size_t keep = ctx->src_len > window ? window : ctx->src_len;
            size_t drop = ctx->src_len - keep;
            if (drop > 0) {
                memmove(ctx->src_buf, ctx->src_buf + drop, keep);
                ctx->src_len = keep;
                /* Adjust matcher table/chain entries: positions were
                 * relative to src_buf[0] and are now shifted by -drop.
                 * Easiest correct approach: invalidate chains — they
                 * reference positions < limit automatically and are
                 * bounded-distance walked. The hash table's `table[h]`
                 * entries would now point at shifted positions, but
                 * we can shift them en masse. */
                /* Shift matcher table entries (positions get re-based) */
                for (uint32_t i = 0; i < VV_HC_SIZE; i++) {
                    if (ctx->m.table[i] >= (int32_t)drop)
                        ctx->m.table[i] -= (int32_t)drop;
                    else ctx->m.table[i] = -1;
                }
                for (uint32_t i = 0; i < VV_HC4_SIZE; i++) {
                    if (ctx->m.table4[i] >= (int32_t)drop)
                        ctx->m.table4[i] -= (int32_t)drop;
                    else ctx->m.table4[i] = -1;
                }
                /* Chain arrays are also indexed by position — shift those
                 * too, BUT the array is indexed by (pos & chain_mask) so
                 * we need to shift values (the successor position) while
                 * keeping the circular layout. For simplicity and safety,
                 * we rebuild conservatively: clear chain entries whose
                 * references would now be negative. */
                for (uint32_t i = 0; i < (1u << ctx->wlog); i++) {
                    if (ctx->m.chain[i] >= (int32_t)drop)
                        ctx->m.chain[i] -= (int32_t)drop;
                    else ctx->m.chain[i] = -1;
                    if (ctx->m.hash4_chain[i] >= (int32_t)drop)
                        ctx->m.hash4_chain[i] -= (int32_t)drop;
                    else ctx->m.hash4_chain[i] = -1;
                }
            }
        }
        memcpy(ctx->src_buf + ctx->src_len, chunk, chunk_len);
        ctx->src_len += chunk_len;
        ctx->global_offset += chunk_len;

        if (ctx->opts.checksum) vv_xxh64_update(&ctx->cks, chunk, chunk_len);
    }

    /* Emit block(s) for the newly added chunk_len bytes.
     * block_start in the src_buf = ctx->src_len - chunk_len. */
    if (chunk_len == 0 && is_last) {
        /* Empty final chunk: emit empty raw-last block */
        if (cap_left < 4) return VV_ERR_OVERFLOW;
        uint32_t bh = vv_bh_pack(VV_BLOCK_RAW, 1, 0);
        memcpy(op, &bh, 4); op += 4; cap_left -= 4;
    } else if (chunk_len > 0) {
        size_t block_start = ctx->src_len - chunk_len;
        int stream_min_match = ctx->opts.format_v2 ? 3 : (int)VV_MIN_MATCH;
        size_t block_sz = emit_block(ctx->src_buf, block_start, chunk_len, is_last,
                                     &ctx->m, ctx->opts.mode, ctx->wlog,
                                     ctx->tmp, ctx->tcap,
                                     ctx->lit_buf, ctx->lit_cap,
                                     ctx->stripped, ctx->ent_buf, ctx->ent_cap,
                                     op, cap_left, stream_min_match,
                                     ctx->opts.compat_v246_5_decoder,
                                     NULL /* stream scrubs full caps at destroy */);
        if (block_sz == 0) return VV_ERR_OVERFLOW;
        op += block_sz; cap_left -= block_sz;
    }

    /* Emit frame footer on last chunk */
    if (is_last && ctx->opts.checksum) {
        if (cap_left < sizeof(vv_frame_footer_t)) return VV_ERR_OVERFLOW;
        vv_frame_footer_t ff;
        ff.checksum = vv_xxh64_finalize(&ctx->cks);
        ff.footer_magic = 0x56564E44u;
        memcpy(op, &ff, sizeof(ff));
        op += sizeof(ff);
        /* cap_left no longer read — function returns immediately below */
    }

    *written = (size_t)(op - dst);
    return VV_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * MULTI-THREADED COMPRESSION
 *
 * Strategy: split input into chunks of chunk_size bytes. Each chunk
 * is encoded independently via vv_compress() into its own .vv frame.
 * Output frames are concatenated into dst. vv_decompress handles
 * multi-frame input natively.
 *
 * When VV_ENABLE_THREADS is defined, use pthread to run N worker
 * threads in parallel. Otherwise, run sequentially.
 *
 * Ratio cost: frames are independent — cross-frame match history
 * is lost at chunk boundaries. For chunk_size ≥ 4 MB on
 * compressible data, the ratio hit is typically < 2%.
 * ═══════════════════════════════════════════════════════════════ */

#ifdef VV_ENABLE_THREADS
#include <pthread.h>
#include <unistd.h>

typedef struct {
    const uint8_t *src;
    size_t src_len;
    uint8_t *dst;
    size_t dst_cap;
    const vv_options_t *opts;
    int64_t result;  /* compressed size, or error code */
} mt_task_t;

typedef struct {
    mt_task_t *tasks;
    size_t ntasks;
    /* SPRINT 98 audit: removed redundant `volatile`. next_task is
     * protected by the mutex below, which provides full memory
     * ordering. `volatile` was misleading — it doesn't provide
     * synchronization, only prevents compiler reordering, and the
     * mutex already prevents both. */
    size_t next_task;
    pthread_mutex_t mutex;
} mt_pool_t;

static void *mt_worker(void *arg) {
    mt_pool_t *pool = (mt_pool_t *)arg;
    for (;;) {
        pthread_mutex_lock(&pool->mutex);
        size_t idx = pool->next_task++;
        pthread_mutex_unlock(&pool->mutex);
        if (idx >= pool->ntasks) break;
        mt_task_t *t = &pool->tasks[idx];
        t->result = vv_compress(t->src, t->src_len, t->dst, t->dst_cap, t->opts);
    }
    return NULL;
}
#endif

int64_t vv_compress_mt(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap,
                       const vv_options_t *opts,
                       unsigned int nthreads,
                       size_t chunk_size) {
    /* SPRINT 95 audit: same as vv_compress — accept NULL opts and
     * src_len=0 for API consistency. */
    if (!dst) return VV_ERR_PARAM;
    if (src_len > 0 && !src) return VV_ERR_PARAM;
    vv_options_t local_opts;
    if (!opts) {
        vv_default_options(&local_opts);
        opts = &local_opts;
    }
    if (chunk_size == 0) chunk_size = 4 * 1024 * 1024;  /* 4 MB default */
    if (chunk_size < VV_MAX_BLOCK_SIZE) chunk_size = VV_MAX_BLOCK_SIZE;

    /* For small inputs, just use vv_compress directly — no speedup
     * available and avoids the per-frame fixed overhead. */
    if (src_len <= chunk_size) {
        return vv_compress(src, src_len, dst, dst_cap, opts);
    }

    /* Split into N chunks */
    size_t n_chunks = (src_len + chunk_size - 1) / chunk_size;

    /* Allocate per-chunk temporary output buffers. Each could be up to
     * vv_compress_bound(chunk_size), which can be ~4 MB * 1.01 for a
     * 4 MB chunk. Total scratch = n_chunks * ~4 MB. */
    uint8_t **chunk_dst = (uint8_t **)calloc(n_chunks, sizeof(uint8_t *));
    int64_t *chunk_sz = (int64_t *)calloc(n_chunks, sizeof(int64_t));
    if (!chunk_dst || !chunk_sz) {
        free(chunk_dst); free(chunk_sz);
        return VV_ERR_NOMEM;
    }

    size_t chunk_cap = vv_compress_bound(chunk_size);
    int alloc_failed = 0;
    for (size_t i = 0; i < n_chunks; i++) {
        chunk_dst[i] = (uint8_t *)malloc(chunk_cap);
        if (!chunk_dst[i]) { alloc_failed = 1; break; }
    }
    if (alloc_failed) {
        for (size_t i = 0; i < n_chunks; i++) free(chunk_dst[i]);
        free(chunk_dst); free(chunk_sz);
        return VV_ERR_NOMEM;
    }

#ifdef VV_ENABLE_THREADS
    /* Determine thread count */
    if (nthreads == 0) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        nthreads = (n > 0) ? (unsigned int)n : 1;
    }
    if (nthreads > n_chunks) nthreads = (unsigned int)n_chunks;
    if (nthreads == 0) nthreads = 1;

    /* Build task list */
    mt_task_t *tasks = (mt_task_t *)malloc(n_chunks * sizeof(mt_task_t));
    if (!tasks) {
        for (size_t i = 0; i < n_chunks; i++) free(chunk_dst[i]);
        free(chunk_dst); free(chunk_sz);
        return VV_ERR_NOMEM;
    }
    for (size_t i = 0; i < n_chunks; i++) {
        size_t off = i * chunk_size;
        size_t len = (off + chunk_size <= src_len) ? chunk_size : (src_len - off);
        tasks[i].src = src + off;
        tasks[i].src_len = len;
        tasks[i].dst = chunk_dst[i];
        tasks[i].dst_cap = chunk_cap;
        tasks[i].opts = opts;
        tasks[i].result = 0;
    }

    mt_pool_t pool;
    pool.tasks = tasks;
    pool.ntasks = n_chunks;
    pool.next_task = 0;
    pthread_mutex_init(&pool.mutex, NULL);

    pthread_t *threads = (pthread_t *)malloc(nthreads * sizeof(pthread_t));
    if (!threads) {
        pthread_mutex_destroy(&pool.mutex);
        free(tasks);
        for (size_t i = 0; i < n_chunks; i++) free(chunk_dst[i]);
        free(chunk_dst); free(chunk_sz);
        return VV_ERR_NOMEM;
    }
    for (unsigned int t = 0; t < nthreads; t++)
        pthread_create(&threads[t], NULL, mt_worker, &pool);
    for (unsigned int t = 0; t < nthreads; t++)
        pthread_join(threads[t], NULL);
    free(threads);
    pthread_mutex_destroy(&pool.mutex);

    for (size_t i = 0; i < n_chunks; i++) chunk_sz[i] = tasks[i].result;
    free(tasks);
#else
    /* Sequential fallback: encode each chunk in turn. */
    (void)nthreads;
    for (size_t i = 0; i < n_chunks; i++) {
        size_t off = i * chunk_size;
        size_t len = (off + chunk_size <= src_len) ? chunk_size : (src_len - off);
        chunk_sz[i] = vv_compress(src + off, len, chunk_dst[i], chunk_cap, opts);
    }
#endif

    /* Check for errors and total up sizes */
    int64_t total = 0;
    for (size_t i = 0; i < n_chunks; i++) {
        if (chunk_sz[i] < 0) {
            int64_t err = chunk_sz[i];
            for (size_t j = 0; j < n_chunks; j++) free(chunk_dst[j]);
            free(chunk_dst); free(chunk_sz);
            return err;
        }
        total += chunk_sz[i];
    }

    if ((size_t)total > dst_cap) {
        for (size_t i = 0; i < n_chunks; i++) free(chunk_dst[i]);
        free(chunk_dst); free(chunk_sz);
        return VV_ERR_OVERFLOW;
    }

    /* Concatenate frames into dst */
    uint8_t *op = dst;
    for (size_t i = 0; i < n_chunks; i++) {
        memcpy(op, chunk_dst[i], (size_t)chunk_sz[i]);
        op += chunk_sz[i];
        free(chunk_dst[i]);
    }
    free(chunk_dst); free(chunk_sz);

    return total;
}
