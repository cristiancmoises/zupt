/* VaptVupt codec — originally Apache-2.0 by Cristian Cezar Moisés
 * Integrated into Zupt — MIT License
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT AND Apache-2.0
 */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif
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
    __builtin_memcpy(&lo, p, 4);
    uint64_t v = (uint64_t)lo | ((uint64_t)p[4] << 32);
    /* Shift by (64 - HC_BITS) to get the top HC_BITS of the product */
    return (uint32_t)((v * 889523592379ULL) >> (64 - VV_HC_BITS));
}

/* 4-byte hash for positions near end of buffer */
static inline uint32_t hash4(const uint8_t *p) {
    uint32_t v;
    __builtin_memcpy(&v, p, 4);
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
        if (mask) return len + (int32_t)__builtin_ctz(mask);
        len += 32;
    }
#endif
    while (len < max_len && a[len] == b[len]) len++;
    return len;
}

/* ═══════════════════════════════════════════════════════════════
 * MATCHER: hash chain with 5-byte hash + rep-match
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    int32_t *table;    /* Hash table: VV_HC_SIZE entries, heap-allocated */
    int32_t *chain;    /* Chain array: window_size entries */
    uint32_t chain_mask;
    uint32_t chain_depth;
    uint32_t rep[3];   /* 3 most recent match offsets */
    uint8_t  wlog;     /* Window log: controls max offset distance */
} matcher_t;

static void matcher_init(matcher_t *m, uint32_t window_log, uint32_t depth) {
    uint32_t wsz = 1u << window_log;
    m->table = (int32_t *)malloc(VV_HC_SIZE * sizeof(int32_t));
    m->chain = (int32_t *)malloc(wsz * sizeof(int32_t));
    memset(m->table, 0xFF, VV_HC_SIZE * sizeof(int32_t));  /* -1 */
    memset(m->chain, 0xFF, wsz * sizeof(int32_t));          /* -1 */
    m->chain_mask = wsz - 1;
    m->chain_depth = depth;
    m->rep[0] = m->rep[1] = m->rep[2] = 0;
    m->wlog = (uint8_t)window_log;
}

static void matcher_free(matcher_t *m) {
    free(m->table); m->table = NULL;
    free(m->chain); m->chain = NULL;
}

static inline void matcher_insert(matcher_t *m, const uint8_t *data,
                                   int32_t pos, int32_t end) {
    if (pos + 4 > end) return;
    uint32_t h = hash_safe(data + pos, end - pos);
    m->chain[pos & m->chain_mask] = m->table[h];
    m->table[h] = pos;
}

/* ─── Rep-match check: O(1), checked BEFORE hash probe ─── */
static inline int32_t try_rep_match(const matcher_t *m, const uint8_t *data,
                                     int32_t pos, int32_t end,
                                     int32_t *rep_idx) {
    for (int i = 0; i < 3; i++) {
        uint32_t d = m->rep[i];
        if (d == 0 || (uint32_t)pos < d) continue;
        int32_t ref = pos - (int32_t)d;
        /* Quick 4-byte check */
        uint32_t a, b;
        __builtin_memcpy(&a, data + pos, 4);
        __builtin_memcpy(&b, data + ref, 4);
        if (a == b) {
            int32_t max = end - pos;
            if (max > VV_MAX_MATCH) max = VV_MAX_MATCH;
            int32_t len = 4 + extend_match(data + pos + 4, data + ref + 4, max - 4);
            *rep_idx = i;
            return len;
        }
    }
    return 0;
}

/* ─── Hash chain match: uses 5-byte hash, searches up to chain_depth ─── */
static int32_t chain_match(const matcher_t *m, const uint8_t *data,
                            int32_t pos, int32_t end, int32_t *best_off) {
    if (pos + 4 > end) return 0;
    uint32_t h = hash_safe(data + pos, end - pos);
    int32_t ref = m->table[h];
    int32_t best_len = 0;
    *best_off = 0;

    uint32_t depth = m->chain_depth;
    /* PERF: match distance limit derived from window log.
     * wlog=16 → 65535, wlog=20 → 1048575, wlog=22 → 4194303. */
    int32_t max_dist = (int32_t)((1u << m->wlog) - 1);
    int32_t limit = pos - max_dist;
    if (limit < 0) limit = 0;

    while (ref >= 0 && ref >= limit && ref < pos && depth-- > 0) {
        /* Quick 4-byte prefix check */
        uint32_t a, b;
        __builtin_memcpy(&a, data + pos, 4);
        __builtin_memcpy(&b, data + ref, 4);
        if (a == b) {
            int32_t max = end - pos;
            if (max > VV_MAX_MATCH) max = VV_MAX_MATCH;
            int32_t len = 4 + extend_match(data + pos + 4, data + ref + 4, max - 4);
            if (len > best_len) {
                best_len = len;
                *best_off = pos - ref;
                if (len >= 256) break; /* good enough */
            }
        }
        ref = m->chain[ref & m->chain_mask];
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
                        size_t ll, size_t ml, uint32_t off, int off_bytes) {
    uint8_t *op = dst;

    uint8_t ll_f = (ll >= 15) ? 15 : (uint8_t)ll;
    uint8_t ml_f;
    if (ml == 0) { ml_f = 0; }
    else { size_t v = ml - VV_MIN_MATCH; ml_f = (v >= 15) ? 15 : (uint8_t)v; }

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
        if (ml - VV_MIN_MATCH >= 15)
            op += write_varint(op, ml - VV_MIN_MATCH - 15);
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

static size_t compress_block(const uint8_t *src, size_t src_len,
                             uint8_t *dst, size_t dst_cap,
                             matcher_t *m, vv_mode_t mode) {
    uint8_t *op = dst;
    int32_t pos = 0;
    int32_t end = (int32_t)src_len;
    const uint8_t *lit_start = src;
    int off_bytes = (m->wlog > 16) ? 3 : 2;

    while (pos < end - (int32_t)VV_MIN_MATCH) {
        int32_t mlen = 0, moff = 0;

        /* ─── Step 1: Try rep-match (free, no hash lookup) ─── */
        int32_t rep_idx = -1;
        int32_t rep_len = try_rep_match(m, src, pos, end, &rep_idx);

        if (rep_len >= (int32_t)VV_MIN_MATCH) {
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
        if (mode >= VV_MODE_BALANCED && mlen >= (int32_t)VV_MIN_MATCH &&
            pos + 1 < end - (int32_t)VV_MIN_MATCH) {
            /* Check pos+1 */
            matcher_insert(m, src, pos, end);
            int32_t noff = 0;
            int32_t nlen = chain_match(m, src, pos + 1, end, &noff);

            /* Also check rep at pos+1 */
            int32_t nri = -1;
            int32_t nrl = try_rep_match(m, src, pos + 1, end, &nri);
            if (nrl > nlen) { nlen = nrl; noff = (int32_t)m->rep[nri]; }

            if (nlen > mlen + 1) {
                /* pos+1 is significantly better: emit literal, shift */
                pos++;
                mlen = nlen; moff = noff;

                /* Lazy-2: also check pos+2 (extreme mode) */
                if (mode >= VV_MODE_EXTREME && pos + 1 < end - (int32_t)VV_MIN_MATCH) {
                    matcher_insert(m, src, pos, end);
                    int32_t n2off = 0;
                    int32_t n2len = chain_match(m, src, pos + 1, end, &n2off);
                    int32_t n2ri = -1;
                    int32_t n2rl = try_rep_match(m, src, pos + 1, end, &n2ri);
                    if (n2rl > n2len) { n2len = n2rl; n2off = (int32_t)m->rep[n2ri]; }
                    if (n2len > mlen + 1) {
                        pos++;
                        mlen = n2len; moff = n2off;
                    }
                }
            }
        }

        /* ─── Step 4: Emit sequence or literal ─── */
        if (mlen >= (int32_t)VV_MIN_MATCH) {
            size_t ll = (size_t)(src + pos - lit_start);
            size_t needed = 1 + (ll >= 15 ? ll / 255 + 2 : 0)
                          + ll + 2 + ((size_t)mlen / 255 + 2);
            if ((size_t)(op - dst) + needed > dst_cap) return 0;

            op += emit_seq(op, lit_start, ll, (size_t)mlen, (uint32_t)moff, off_bytes);

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
        op += emit_seq(op, lit_start, ll, 0, 0, off_bytes);
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
        case VV_MODE_BALANCED:   wlog = 16; break;
        case VV_MODE_EXTREME:    wlog = 16; break;
        /* TRADEOFF: wlog=16 default avoids 3-byte offset overhead on small data.
         * Users can set opts.window_log=20 (1MB) or 22 (4MB) for large files
         * with long-range patterns. Zupt sets wlog=20 for backup chunks >1MB. */
        }
    }
    switch (opts->mode) {
    case VV_MODE_ULTRA_FAST: depth = 4; break;
    case VV_MODE_BALANCED:   depth = 48; break;
    case VV_MODE_EXTREME:    depth = 256; break;
    default: depth = 48;
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

    /* Temp buffer */
    size_t tcap = VV_MAX_BLOCK_SIZE + VV_MAX_BLOCK_SIZE / 255 + 1024;
    uint8_t *tmp = (uint8_t *)malloc(tcap);
    if (!tmp) { matcher_free(&m); return VV_ERR_NOMEM; }

    /* Additional buffers for entropy path (only allocated if needed) */
    uint8_t *lit_buf = NULL, *stripped = NULL, *ent_buf = NULL;
    size_t lit_cap = 0, ent_cap = 0;
    if (opts->mode >= VV_MODE_BALANCED) {
        lit_cap = VV_MAX_BLOCK_SIZE;
        ent_cap = vva_bound(VV_MAX_BLOCK_SIZE);
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

    while (remaining > 0) {
        size_t braw = remaining > VV_MAX_BLOCK_SIZE ? VV_MAX_BLOCK_SIZE : remaining;
        int last = (remaining <= VV_MAX_BLOCK_SIZE);

        size_t csz = compress_block(ip, braw, tmp, tcap, &m, opts->mode);

        if (csz == 0 || csz >= braw) {
            /* Incompressible: store raw */
            uint32_t bh = vv_bh_pack(VV_BLOCK_RAW, last, (uint32_t)braw);
            memcpy(op, &bh, 4); op += 4;
            memcpy(op, ip, braw); op += braw;
        } else if (opts->mode >= VV_MODE_BALANCED) {
            /* ═══ WINNER-TAKES-ALL block selection ═══
             * TRADEOFF: we encode the block twice (once 'S', once 'I'/'C')
             * and pick the smaller. This costs ~2× encode time but ensures
             * we NEVER regress ratio vs any previous codec version.
             * Encode speed is not the bottleneck (decode is). */

            /* ── Path A: sequence coding ('S') ── */
            size_t seq_len = 0;
            int seq_valid = 0;
            size_t seq_block_sz = (size_t)-1; /* Total bytes if we emit 'S' */
            int off_bytes = (wlog > 16) ? 3 : 2;
            vva_error_t serr = vva_encode_sequences(tmp, csz,
                                                     ent_buf, ent_cap, &seq_len, off_bytes);
            if (serr == VVA_OK) {
                seq_block_sz = 4 + 3 + 1 + seq_len; /* block_hdr + comp_sz + tag + data */
                seq_valid = 1;
            }

            /* ── Path B: literal-only entropy ('I' or 'C') ── */
            size_t stripped_len = 0;
            size_t lit_count = extract_literals(tmp, csz, lit_buf, lit_cap,
                                                stripped, &stripped_len, off_bytes);

            /* Use second half of ent_buf for path B to avoid overwriting path A */
            uint8_t *ent_buf2 = ent_buf + ent_cap / 2;
            size_t ent_cap2 = ent_cap / 2;
            size_t ent_len = 0;
            uint8_t ent_tag = 0;
            size_t ent_block_sz = (size_t)-1;

            if (lit_count > 0) {
                if (opts->mode >= VV_MODE_EXTREME && lit_count >= 64) {
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

            /* ── Path C: raw type-1 block ── */
            size_t raw_block_sz = 4 + 3 + csz;

            /* ── Pick winner ── */
            if (seq_valid && seq_block_sz <= ent_block_sz && seq_block_sz < raw_block_sz) {
                /* 'S' wins — emit sequence-coded block */
                uint32_t bh = vv_bh_pack(VV_BLOCK_ENTROPY, last, (uint32_t)braw);
                memcpy(op, &bh, 4); op += 4;
                uint32_t total_comp = (uint32_t)(1 + seq_len);
                op[0] = (uint8_t)(total_comp);
                op[1] = (uint8_t)(total_comp >> 8);
                op[2] = (uint8_t)(total_comp >> 16);
                op += 3;
                *op++ = VV_ENTROPY_SEQ;
                memcpy(op, ent_buf, seq_len); op += seq_len;
            } else if (ent_tag && ent_block_sz < raw_block_sz) {
                /* 'I'/'C' wins — emit literal-entropy block */
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
            } else {
                /* Raw type-1 wins (or nothing compresses) */
                uint32_t bh = vv_bh_pack(VV_BLOCK_COMPRESSED, last, (uint32_t)braw);
                memcpy(op, &bh, 4); op += 4;
                op[0] = (uint8_t)(csz); op[1] = (uint8_t)(csz >> 8); op[2] = (uint8_t)(csz >> 16);
                op += 3;
                memcpy(op, tmp, csz); op += csz;
            }
        } else {
            /* Ultra-fast mode: emit type 1 block directly */
            uint32_t bh = vv_bh_pack(VV_BLOCK_COMPRESSED, last, (uint32_t)braw);
            memcpy(op, &bh, 4); op += 4;
            op[0] = (uint8_t)(csz); op[1] = (uint8_t)(csz >> 8); op[2] = (uint8_t)(csz >> 16);
            op += 3;
            memcpy(op, tmp, csz); op += csz;
        }
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
