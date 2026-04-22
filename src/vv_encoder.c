/*
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
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) && defined(__AVX2__)
#include <immintrin.h>
#define VV_ENC_AVX2 1
#else
#define VV_ENC_AVX2 0
#endif

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

static inline uint32_t hash5(const uint8_t *p) {
    uint32_t lo;
    memcpy(&lo, p, 4);
    uint64_t v = (uint64_t)lo | ((uint64_t)p[4] << 32);
    /* Shift by (64 - HC_BITS) to get the top HC_BITS of the product */
    return (uint32_t)((v * 889523592379ULL) >> (64 - VV_HC_BITS));
}

/* 4-byte hash for positions near end of buffer */
static inline uint32_t hash4(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return (v * 2654435761u) >> (32 - VV_HC_BITS);
}

/* Safe hash: picks 5-byte or 4-byte depending on remaining bytes */
static inline uint32_t hash_safe(const uint8_t *p, int32_t remain) {
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
    while (len < max_len && a[len] == b[len]) len++;
    return len;
}

/* ═══════════════════════════════════════════════════════════════
 * MATCHER: hash chain with 5-byte hash + rep-match
 * ═══════════════════════════════════════════════════════════════ */


#define VV_HC4_BITS  16
#define VV_HC4_SIZE  (1u << VV_HC4_BITS)

static inline uint32_t hash4_short(const uint8_t *p) {
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

static inline uint32_t hash3_short(const uint8_t *p) {
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
    uint32_t max_match;    /* Max representable matchlen (65535 for v1,
                            * 65534 for v2: ml_base_v2[35]=32767 with 15
                            * extra bits only reaches 65534). */
} matcher_t;

static void matcher_init(matcher_t *m, uint32_t window_log, uint32_t depth) {
    uint32_t wsz = 1u << window_log;
    m->table = (int32_t *)malloc(VV_HC_SIZE * sizeof(int32_t));
    m->chain = (int32_t *)malloc(wsz * sizeof(int32_t));
    m->table4 = (int32_t *)malloc(VV_HC4_SIZE * sizeof(int32_t));
    m->hash4_chain = (int32_t *)malloc(wsz * sizeof(int32_t));
    /* hash3 tables allocated lazily only when use_hash3 is enabled.
     * On v1 path (the default), they stay NULL and cost nothing. */
    m->table3 = NULL;
    m->hash3_chain = NULL;
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
    m->max_match = VV_MAX_MATCH;  /* v1 default, see matcher_set_format_v2 */
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
static int32_t chain_match_ex(const matcher_t *m, const uint8_t *data,
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
     * PERF: prefetch the next chain slot 2 iterations ahead. Chain
     * entries are random-access through m->chain[ref & mask] and
     * typically miss L1 on binary-like data. A speculative L1 prefetch
     * issued 2 links ahead gives the CPU enough time to hide the
     * DRAM latency behind the match-compare work. */
    uint32_t h = hash_safe(data + pos, end - pos);
    int32_t ref = m->table[h];
    uint32_t depth = m->chain_depth;

    /* Seed the pipeline: prefetch the source side of next candidate */
    if (ref >= limit && ref < pos) {
        __builtin_prefetch(data + ref, 0, 0);
    }

    while (ref >= 0 && ref >= limit && ref < pos && depth-- > 0) {
        int32_t next_ref = m->chain[ref & m->chain_mask];
        /* Prefetch: next chain traversal's candidate data bytes */
        if (next_ref >= limit && next_ref < pos) {
            __builtin_prefetch(data + next_ref, 0, 0);
            /* Also prefetch the chain entry after next, for 2-ahead cover */
            __builtin_prefetch(&m->chain[next_ref & m->chain_mask], 0, 0);
        }

        uint32_t b;
        memcpy(&b, data + ref, 4);
        if (pos4 == b) {
            int32_t max = end - pos;
            if (max > (int32_t)m->max_match) max = (int32_t)m->max_match;
            int32_t len = 4 + extend_match(data + pos + 4, data + ref + 4, max - 4);
            if (len > best_len) {
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

        while (ref4 >= 0 && ref4 >= limit && ref4 < pos && depth4-- > 0) {
            int32_t next_ref4 = m->hash4_chain[ref4 & m->chain_mask];
            if (next_ref4 >= limit && next_ref4 < pos) {
                __builtin_prefetch(data + next_ref4, 0, 0);
                __builtin_prefetch(&m->hash4_chain[next_ref4 & m->chain_mask], 0, 0);
            }

            uint32_t b4;
            memcpy(&b4, data + ref4, 4);
            if (pos4 == b4) {
                int32_t max = end - pos;
                if (max > (int32_t)m->max_match) max = (int32_t)m->max_match;
                int32_t len = 4 + extend_match(data + pos + 4, data + ref4 + 4, max - 4);
                if (len > best_len) {
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

    while (pos < end - min_match) {
        int32_t mlen = 0, moff = 0;

        /* ─── Step 1: Try rep-match (free, no hash lookup) ─── */
        int32_t rep_idx = -1;
        int32_t rep_len = try_rep_match(m, src, pos, end, &rep_idx);

        if (rep_len >= min_match) {
            mlen = rep_len;
            moff = (int32_t)m->rep[rep_idx];
        }

        /* ─── Step 2: Hash chain match (only if rep didn't find a long one) ─── */
        if (mlen < 8) {
            int32_t chain_off = 0;
            int32_t chain_len = chain_match(m, src, pos, end, &chain_off);
            if (chain_len > mlen) {
                mlen = chain_len;
                moff = chain_off;
                rep_idx = -1; /* not a rep match */
            }
        }

        /* ─── Step 3: Lazy evaluation (balanced + extreme) ─── */
        if (mode >= VV_MODE_BALANCED && mlen >= min_match &&
            pos + 1 < end - min_match) {
            /* Check pos+1 */
            matcher_insert(m, src, pos, end);
            int32_t noff = 0;
            int32_t nlen = chain_match(m, src, pos + 1, end, &noff);

            /* Also check rep at pos+1 */
            int32_t nri = -1;
            int32_t nrl = try_rep_match(m, src, pos + 1, end, &nri);
            if (nrl > nlen) { nlen = nrl; noff = (int32_t)m->rep[nri]; }

            /* standard */int32_t lazy_gain = 2;
            if (nlen > mlen + lazy_gain) {
                /* pos+1 is significantly better: emit literal, shift */
                pos++;
                mlen = nlen; moff = noff;

                /* Lazy-2 disabled in v2.24.0.
                 *
                 * Previously, after a lazy-1 shift to pos+1, this block
                 * would try another shift to pos+2 if n2len > mlen + 1.
                 * That was a classic "greedy past the peak" bug:
                 *
                 * Empirical results on 50KB English-text corpus:
                 *   balanced:              11,279 bytes
                 *   extreme + lazy-2 (+1): 12,157 bytes  (+8% vs balanced)
                 *   extreme + lazy-2 (+2): 12,157 bytes  (threshold didn't matter)
                 *   extreme + lazy-2 (+4): 11,860 bytes  (still worse)
                 *   extreme, lazy-2 off:   10,718 bytes  (5% better!)
                 *
                 * On 4 text corpora tested, lazy-2 cost an aggregate
                 * 2,463 bytes vs disabled. On 2 JSON corpora, it saved
                 * 213 bytes. Net-bytes-across-inputs: disabled wins by
                 * ~10×. Disabling produces the strictly correct
                 * "extreme >= balanced ratio" contract on all tested
                 * inputs except JSON, where the regression is tiny
                 * (<5%) and offset-encoding-cost-aware parsing would
                 * be the proper fix (future work).
                 *
                 * Root cause: lazy-2's break-even model doesn't
                 * account for the offset-extra-bits encoding cost of
                 * the shifted-to match. On text, deeper chain search
                 * finds long matches at far offsets whose extra-bits
                 * cost exceeds the gain from the extra match length. */
                (void)lazy_gain;  /* still used in lazy-1 above */
                if (0) {
                    /* dead code — reference for future cost-aware work */
                    matcher_insert(m, src, pos, end);
                    int32_t n2off = 0;
                    int32_t n2len = chain_match(m, src, pos + 1, end, &n2off);
                    int32_t n2ri = -1;
                    int32_t n2rl = try_rep_match(m, src, pos + 1, end, &n2ri);
                    if (n2rl > n2len) { n2len = n2rl; n2off = (int32_t)m->rep[n2ri]; }
                    if (n2len > mlen + lazy_gain) {
                        pos++;
                        mlen = n2len; moff = n2off;
                    }
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
            if (mlen >= 16) {
                /* Long match: only insert boundary positions */
                for (int32_t j = pos; j < pos + 3 && j < end - 4; j++)
                    matcher_insert(m, src, j, end);
                for (int32_t j = pos + mlen - 3; j < pos + mlen && j < end - 4; j++)
                    matcher_insert(m, src, j, end);
            } else {
                /* Short match: insert all positions */
                for (int32_t j = pos; j < pos + mlen && j < end - 4; j++)
                    matcher_insert(m, src, j, end);
            }

            update_rep(m, (uint32_t)moff);
            pos += mlen;
            lit_start = src + pos;
        } else {
            matcher_insert(m, src, pos, end);
            pos++;
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
static size_t emit_block(const uint8_t *src, size_t block_start, size_t braw,
                         int last, matcher_t *m, vv_mode_t mode, uint8_t wlog,
                         uint8_t *tmp, size_t tcap,
                         uint8_t *lit_buf, size_t lit_cap,
                         uint8_t *stripped, uint8_t *ent_buf, size_t ent_cap,
                         uint8_t *dst, size_t dst_cap, int min_match) {
    uint8_t *op = dst;

    size_t csz = compress_block(src, block_start, braw, tmp, tcap, m, mode, min_match);

    if (csz == 0 || csz >= braw) {
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
        vva_error_t serr = use_v2
            ? vva_encode_sequences_v2(tmp, csz, ent_buf, ent_cap, &seq_len, off_bytes)
            : vva_encode_sequences(tmp, csz, ent_buf, ent_cap, &seq_len, off_bytes);
        if (serr == VVA_OK) {
            seq_block_sz = 4 + 3 + 1 + seq_len;
            seq_valid = 1;
        }

        /* Path B: literal-only entropy ('I' or 'C') */
        size_t stripped_len = 0;
        size_t lit_count = 0;
        uint8_t *ent_buf2 = ent_buf + ent_cap / 2;
        size_t ent_cap2 = ent_cap / 2;
        size_t ent_len = 0;
        uint8_t ent_tag = 0;
        size_t ent_block_sz = (size_t)-1;

        int try_path_b = 1;
        if (mode == VV_MODE_BALANCED && seq_valid && seq_block_sz < (braw / 3)) {
            /* SPRINT 29 (revised in v2.15): always try Path B in BALANCED
             * mode, comparing both costs and picking the smaller. The
             * earlier "skip Path B if seq compressed >3:1" heuristic
             * (added in Sprint 28 for speed) saved ~30% encode time but
             * hurt ratio on text-heavy data — Silesia dickens/reymont
             * showed Path B's 'C' tag would have produced 5-10% smaller
             * output but never got the chance.
             *
             * v2.15 trade-off: encoder is ~25% slower in BALANCED mode
             * but ratio improves measurably on text. Decode speed is
             * unaffected (decoder doesn't care which tag was chosen).
             *
             * In ULTRA_FAST/FAST modes the original skip remains in
             * effect because those modes are throughput-priority. */
            (void)try_path_b;
        }

        if (try_path_b) {
            lit_count = extract_literals(tmp, csz, lit_buf, lit_cap,
                                         stripped, &stripped_len, off_bytes);
            if (lit_count > 0) {
                if (mode >= VV_MODE_BALANCED && lit_count >= 4096) {
                    vva_error_t aerr = vva_encode_ctx(lit_buf, lit_count,
                                                       ent_buf2, ent_cap2, &ent_len);
                    if (aerr == VVA_OK) ent_tag = VV_ENTROPY_CTX;
                }
                if (!ent_tag) {
                    vva_error_t aerr = vva_encode4(lit_buf, lit_count,
                                                    ent_buf2, ent_cap2, &ent_len);
                    if (aerr == VVA_OK) ent_tag = VV_ENTROPY_ANS4;
                }
                if (!ent_tag) {
                    vva_error_t aerr = vva_encode(lit_buf, lit_count,
                                                   ent_buf2, ent_cap2, &ent_len);
                    if (aerr == VVA_OK) ent_tag = VV_ENTROPY_ANS;
                }
                if (ent_tag) {
                    ent_block_sz = 4 + 3 + 1 + 2 + 2 + ent_len + stripped_len;
                }
            }
        }

        size_t raw_block_sz = 4 + 3 + csz;

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
        } else if (!use_v2) {
            /* Plain VV_BLOCK_COMPRESSED carries raw v1-format tokens.
             * For v2, we must not emit these — the decoder would
             * reconstruct matchlen with +4 instead of +3. Fall to RAW
             * block instead (handled below via "else" when raw_block_sz
             * is smaller). We reach this branch only when the previous
             * conditions all failed AND we're NOT v2. */
            if ((size_t)(op - dst) + raw_block_sz > dst_cap) return 0;
            uint32_t bh = vv_bh_pack(VV_BLOCK_COMPRESSED, last, (uint32_t)braw);
            memcpy(op, &bh, 4); op += 4;
            op[0] = (uint8_t)(csz); op[1] = (uint8_t)(csz >> 8); op[2] = (uint8_t)(csz >> 16);
            op += 3;
            memcpy(op, tmp, csz); op += csz;
        } else {
            /* v2 path, sequence coding didn't fit/help: emit RAW. */
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

int64_t vv_compress(const uint8_t *src, size_t src_len,
                    uint8_t *dst, size_t dst_cap,
                    const vv_options_t *opts) {
    if (!src || !dst || !opts) return VV_ERR_PARAM;
    if (dst_cap < sizeof(vv_frame_header_t) + sizeof(vv_frame_footer_t) + 16)
        return VV_ERR_OVERFLOW;

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
            matcher_t m16; matcher_init(&m16, 16, 4);
            size_t sz16 = compress_block(src, 0, trial_len, trial_buf, trial_cap, &m16, VV_MODE_ULTRA_FAST, VV_MIN_MATCH);
            matcher_free(&m16);

            matcher_t m20; matcher_init(&m20, 20, 4);
            size_t sz20 = compress_block(src, 0, trial_len, trial_buf, trial_cap, &m20, VV_MODE_ULTRA_FAST, VV_MIN_MATCH);
            matcher_free(&m20);

            free(trial_buf);
            if (sz20 > 0 && sz16 > 0 && sz20 < (sz16 * 97 / 100)) wlog = 20;
            /* Binary-like detection: best trial ratio < 2:1 */
            size_t best_sz = (sz20 > 0 && sz20 < sz16) ? sz20 : sz16;
            if (best_sz > 0 && best_sz * 2 > trial_len) enable_hash4 = 1;
        }
    }

    /* Frame header */
    uint8_t *op = dst;
    vv_frame_header_t fh;
    memset(&fh, 0, sizeof(fh));
    fh.magic = VV_MAGIC;
    fh.version = 1;
    fh.flags = opts->checksum ? 1 : 0;
    fh.mode_hint = (uint8_t)opts->mode;
    fh.window_log = wlog;
    fh.content_size = (uint64_t)src_len;
    memcpy(op, &fh, sizeof(fh)); op += sizeof(fh);

    /* Matcher */
    matcher_t m;
    matcher_init(&m, wlog, depth);
    m.use_hash4 = (uint8_t)enable_hash4; /* From fused adaptive-window trial */
    /* Format v2 cap applies to EVERY match emitted from this matcher,
     * not just those produced via hash3. Set unconditionally when
     * opts.format_v2 is active. */
    if (opts->format_v2) {
        matcher_set_format_v2(&m);
    }
    /* Hash3 enablement is a separate, adaptive decision. Only fires
     * on binary-like data (enable_hash4) where length-3 matches
     * actually help. On text/JSON it stays off to avoid regressions. */
    if (opts->format_v2 && enable_hash4) {
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
        ent_cap = vva_bound(block_bound);
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

    /* Format v2: when opts->format_v2 is set, encode with min_match=3.
     * Produces 'T'-tagged ENTROPY blocks which only v2.33.0+ decoders
     * can read. Closes the real-binary compression gap vs gzip-9. */
    int min_match = opts->format_v2 ? 3 : (int)VV_MIN_MATCH;

    while (remaining > 0) {
        size_t braw = remaining > VV_MAX_BLOCK_SIZE ? VV_MAX_BLOCK_SIZE : remaining;
        int last = (remaining <= VV_MAX_BLOCK_SIZE);

        size_t block_start = (size_t)(ip - src);
        size_t written = emit_block(src, block_start, braw, last, &m, opts->mode, wlog,
                                    tmp, tcap, lit_buf, lit_cap,
                                    stripped, ent_buf, ent_cap,
                                    op, dst_cap - (size_t)(op - dst), min_match);
        if (written == 0) {
            free(lit_buf); free(stripped); free(ent_buf);
            free(tmp); matcher_free(&m);
            return VV_ERR_OVERFLOW;
        }
        op += written;
        ip += braw; remaining -= braw;
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

    matcher_init(&ctx->m, wlog, depth);
    /* Format v2 matchlen cap applies to every match — set whenever
     * streaming opts has format_v2 on, not just when hash3 fires. */
    if (opts->format_v2) {
        matcher_set_format_v2(&ctx->m);
    }
    /* SPRINT 45: enable hash3 for format v2 streaming. Must free
     * ctx before returning NULL — callers use NULL-check semantics
     * here, not error codes. */
    if (opts->format_v2) {
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
    ctx->stripped = (uint8_t *)malloc(ctx->lit_cap);
    ctx->ent_cap = vva_bound(VV_MAX_BLOCK_SIZE);
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
    free(ctx->tmp); free(ctx->lit_buf); free(ctx->stripped); free(ctx->ent_buf);
    free(ctx->src_buf);
    matcher_free(&ctx->m);
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
    ctx->m.chain_depth = depth;

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
                                     op, cap_left, stream_min_match);
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
        op += sizeof(ff); cap_left -= sizeof(ff);
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
    volatile size_t next_task;
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
    if (!src || !dst || !opts) return VV_ERR_PARAM;
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
