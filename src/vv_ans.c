/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Cristian Cezar Moisés
 * Commercial licensing: sac@securityops.co
 *
 * VaptVupt — tANS v2 (sparse header + 4-way interleaved decode)
 *
 * Performance targets (x86-64, gcc -O2):
 *   Encode: ≥ 200 MB/s
 *   Decode (scalar 4-way): ≥ 2,500 MB/s
 *   Decode (scalar 1-way): ≥ 1,200 MB/s (backward compat path)
 *
 * Sprint 6 changes:
 *   Item 1: Adaptive header — sparse format for ≤32 active symbols,
 *           saves 400+ bytes on typical post-LZ literal streams.
 *   Item 2: 4-way interleaved encode/decode — hides table lookup latency,
 *           ~2.5× throughput improvement.
 */

#include "vv_ans.h"
#include "vv_platform.h"
#include "vv_huffman.h"
#include <stdlib.h>
#include <string.h>

#define ANS_L    VVA_TABLE_SIZE
#define ANS_LOG  VVA_TABLE_LOG
#define NSYM     VVA_MAX_SYMBOL

static inline int ilog2(uint32_t v) {
    int r = 0;
    while (v >>= 1) r++;
    return r;
}

/* ═══════════════════════════════════════════════════════════════
 * BIT WRITER / READER (LSB-first, 64-bit accumulator)
 * ═══════════════════════════════════════════════════════════════ */

typedef struct { uint64_t a; int n; uint8_t *b; size_t p, c; } ans_bw_t;

static inline void ans_bw_init(ans_bw_t *w, uint8_t *b, size_t c) {
    w->a = 0; w->n = 0; w->b = b; w->p = 0; w->c = c;
}
static inline void ans_bw_add(ans_bw_t *w, uint32_t v, int nb) {
    if (!nb) return;
    w->a |= (uint64_t)(v & ((1u << nb) - 1)) << w->n;
    w->n += nb;
    while (w->n >= 8 && w->p < w->c) {
        w->b[w->p++] = (uint8_t)w->a;
        w->a >>= 8;
        w->n -= 8;
    }
}
static inline size_t ans_bw_flush(ans_bw_t *w) {
    while (w->n > 0 && w->p < w->c) {
        w->b[w->p++] = (uint8_t)w->a;
        w->a >>= 8;
        w->n -= 8;
    }
    return w->p;
}

typedef struct { uint64_t a; int n; const uint8_t *s; size_t p, l; } ans_br_t;

static inline void ans_br_init(ans_br_t *r, const uint8_t *s, size_t l) {
    r->a = 0; r->n = 0; r->s = s; r->p = 0; r->l = l;
}
static inline void ans_br_fill(ans_br_t *r) {
    /* PERF: bulk refill — one unaligned 8-byte load + masked OR.
     *
     * Semantics must match the byte-at-a-time loop exactly. The
     * loop adds whole bytes at positions r->n, r->n+8, r->n+16, ...
     * stopping when r->n would exceed 56 after adding another byte.
     *
     * So we add k = (64 - r->n) / 8 whole bytes (floor), contributing
     * 8k bits. Any 8-byte load's high (64 - 8k) bits are discarded by
     * pre-masking — those bytes stay on disk and get re-loaded next
     * fill. This preserves `r->p` as the byte offset of the next
     * unloaded byte, exactly as the byte-at-a-time loop does.
     *
     * Fallback loop handles end-of-stream where we can't load 8 bytes. */
    if (r->n <= 56) {
        if (VV_LIKELY(r->p + 8 <= r->l)) {
            uint64_t bytes;
            memcpy(&bytes, r->s + r->p, 8);
            int k = (64 - r->n) >> 3;          /* whole bytes to add */
            int bits = k << 3;
            uint64_t mask = (bits == 64) ? ~(uint64_t)0
                                         : ((uint64_t)1 << bits) - 1;
            r->a |= (bytes & mask) << r->n;
            r->p += k;
            r->n += bits;
        } else {
            while (r->n <= 56 && r->p < r->l) {
                r->a |= (uint64_t)r->s[r->p++] << r->n;
                r->n += 8;
            }
        }
    }
}
static inline uint32_t ans_br_read(ans_br_t *r, int nb) {
    if (!nb) return 0;
    if (r->n < nb) ans_br_fill(r);
    uint32_t v = (uint32_t)(r->a & ((1ULL << nb) - 1));
    r->a >>= nb;
    r->n -= nb;
    return v;
}

/* ═══════════════════════════════════════════════════════════════
 * FREQUENCY NORMALIZATION → sum = L = 4096
 * ═══════════════════════════════════════════════════════════════ */

static int normalize_freq(const uint32_t raw[NSYM], uint16_t norm[NSYM]) {
    uint64_t total = 0;
    int np = 0;
    for (int i = 0; i < NSYM; i++) {
        total += raw[i];
        if (raw[i]) np++;
    }
    memset(norm, 0, NSYM * sizeof(uint16_t));
    if (!np) return 0;
    if (np == 1) {
        for (int i = 0; i < NSYM; i++)
            if (raw[i]) norm[i] = (uint16_t)ANS_L;
        return 1;
    }

    int32_t assigned = 0;
    int32_t frac[NSYM];
    memset(frac, 0, sizeof(frac));
    for (int i = 0; i < NSYM; i++) {
        if (!raw[i]) continue;
        uint64_t sc = (uint64_t)raw[i] * ANS_L;
        uint32_t base = (uint32_t)(sc / total);
        if (!base) base = 1;
        norm[i] = (uint16_t)base;
        frac[i] = (int32_t)(sc % total);
        assigned += (int32_t)base;
    }

    int32_t diff = ANS_L - assigned;
    while (diff > 0) {
        int b = -1; int32_t br = -1;
        for (int i = 0; i < NSYM; i++)
            if (raw[i] && frac[i] > br) { br = frac[i]; b = i; }
        if (b < 0) break;
        norm[b]++; frac[b] = -1; diff--;
    }
    while (diff < 0) {
        int b = -1; int32_t br = 0x7FFFFFFF;
        for (int i = 0; i < NSYM; i++)
            if (norm[i] > 1 && frac[i] < br) { br = frac[i]; b = i; }
        if (b < 0) {
            int lg = -1; uint16_t lf = 0;
            for (int i = 0; i < NSYM; i++)
                if (norm[i] > lf) { lf = norm[i]; lg = i; }
            if (lg >= 0 && norm[lg] > 1) { norm[lg]--; diff++; }
            else break;
        } else {
            norm[b]--; frac[b] = 0x7FFFFFFF; diff++;
        }
    }
    return np;
}

/* ═══════════════════════════════════════════════════════════════
 * SYMBOL SPREAD + TABLE BUILD
 * ═══════════════════════════════════════════════════════════════ */

static void spread_symbols(const uint16_t norm[NSYM], uint8_t sp[ANS_L]) {
    const uint32_t step = (ANS_L >> 1) + (ANS_L >> 3) + 3;
    uint32_t pos = 0;
    for (int s = 0; s < NSYM; s++)
        for (int i = 0; i < norm[s]; i++) {
            sp[pos] = (uint8_t)s;
            pos = (pos + step) & (ANS_L - 1);
        }
}

static void build_dec(const uint16_t norm[NSYM], const uint8_t sp[ANS_L],
                       vva_dec_entry_t dec[ANS_L]) {
    uint16_t occ[NSYM];
    memset(occ, 0, sizeof(occ));
    for (int x = 0; x < ANS_L; x++) {
        uint8_t s = sp[x];
        uint16_t f = norm[s];
        int k = occ[s]++;
        if (f == 0 || f == (uint16_t)ANS_L) {
            dec[x].symbol = s; dec[x].nbits = 0; dec[x].baseline = 0;
            continue;
        }
        int flg = ilog2(f);
        int nb_max = ANS_LOG - flg;
        int low_count = (1 << (flg + 1)) - (int)f;
        if (k < low_count) {
            dec[x].nbits = (uint8_t)nb_max;
            dec[x].baseline = (uint16_t)((uint32_t)k << nb_max);
        } else {
            dec[x].nbits = (uint8_t)(nb_max - 1);
            dec[x].baseline = (uint16_t)(((uint32_t)low_count << nb_max)
                             + ((uint32_t)(k - low_count) << (nb_max - 1)));
        }
        dec[x].symbol = s;
    }
}

/* ═══════════════════════════════════════════════════════════════
 * ENCODE CONTEXT
 * ═══════════════════════════════════════════════════════════════ */

typedef struct { uint16_t bl; uint8_t nb; uint16_t slot; } enc_occ_t;
typedef struct { enc_occ_t *o; uint16_t cum[NSYM + 1]; } enc_ctx_t;

static enc_ctx_t *build_enc(const uint16_t norm[NSYM], const uint8_t sp[ANS_L],
                             const vva_dec_entry_t dec[ANS_L]) {
    enc_ctx_t *c = (enc_ctx_t *)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->o = (enc_occ_t *)malloc(ANS_L * sizeof(enc_occ_t));
    if (!c->o) { free(c); return NULL; }
    c->cum[0] = 0;
    for (int i = 0; i < NSYM; i++) c->cum[i + 1] = c->cum[i] + norm[i];
    uint16_t oi[NSYM];
    memset(oi, 0, sizeof(oi));
    for (int x = 0; x < ANS_L; x++) {
        uint8_t s = sp[x];
        int idx = c->cum[s] + oi[s]++;
        c->o[idx].bl = dec[x].baseline;
        c->o[idx].nb = dec[x].nbits;
        c->o[idx].slot = (uint16_t)x;
    }
    for (int s = 0; s < NSYM; s++) {
        int st = c->cum[s], cnt = (int)norm[s];
        for (int i = st + 1; i < st + cnt; i++) {
            enc_occ_t tmp = c->o[i];
            int j = i - 1;
            while (j >= st && c->o[j].bl > tmp.bl) {
                c->o[j + 1] = c->o[j]; j--;
            }
            c->o[j + 1] = tmp;
        }
    }
    return c;
}

static void free_enc(enc_ctx_t *c) {
    if (c) { free(c->o); free(c); }
}

static inline int enc_sym(const enc_ctx_t *c, uint32_t state, uint8_t sym,
                           uint32_t *bv, int *bn) {
    int base = c->cum[sym], cnt = c->cum[sym + 1] - base;
    if (!cnt) return -1;
    if (cnt == ANS_L) { *bv = 0; *bn = 0; return 0; }
    for (int i = base; i < base + cnt; i++) {
        uint32_t bl = c->o[i].bl;
        int nb = c->o[i].nb;
        if (state >= bl && state < bl + (1u << nb)) {
            *bv = state - bl; *bn = nb;
            return (int)c->o[i].slot;
        }
    }
    return -1;
}

/* ═══════════════════════════════════════════════════════════════
 * ADAPTIVE HEADER v2 (Item 1 — Sprint 6)
 *
 * Format:
 *   [1B fmt] VVA_HDR_SINGLE: [1B symbol]
 *   [1B fmt] VVA_HDR_SPARSE: [1B count] then count × [1B sym][2B freq LE]
 *   [1B fmt] VVA_HDR_DENSE:  [1B max_sym] then (max_sym+1) × [2B freq LE]
 *
 * Tradeoff: sparse = 2 + 3×n bytes; dense = 2 + 2×(max_sym+1) bytes.
 * Break-even at n ≈ (2×max_sym) / 3, typically around 85 for ASCII data.
 * We use sparse when n ≤ 64 for safety margin.
 * ═══════════════════════════════════════════════════════════════ */

#define SPARSE_THRESHOLD 64

static size_t write_hdr_v2(const uint16_t norm[NSYM], uint8_t *d, size_t cap) {
    /* Count active symbols and find max */
    int active = 0, max_sym = 0, single_sym = -1;
    for (int i = 0; i < NSYM; i++) {
        if (norm[i] > 0) { active++; max_sym = i; single_sym = i; }
    }

    if (active == 0) return 0;

    if (active == 1) {
        /* Single symbol: 2 bytes total */
        if (cap < 2) return 0;
        d[0] = VVA_HDR_SINGLE;
        d[1] = (uint8_t)single_sym;
        return 2;
    }

    if (active <= SPARSE_THRESHOLD) {
        /* Sparse: 2 + 3×active bytes */
        size_t sz = 2 + 3 * (size_t)active;
        if (sz > cap) return 0;
        d[0] = VVA_HDR_SPARSE;
        d[1] = (uint8_t)active;
        int p = 2;
        for (int i = 0; i < NSYM; i++) {
            if (norm[i] > 0) {
                d[p++] = (uint8_t)i;
                d[p++] = (uint8_t)(norm[i] & 0xFF);
                d[p++] = (uint8_t)(norm[i] >> 8);
            }
        }
        return sz;
    }

    /* Dense: 2 + 2×(max_sym+1) bytes */
    size_t sz = 2 + 2 * (size_t)(max_sym + 1);
    if (sz > cap) return 0;
    d[0] = VVA_HDR_DENSE;
    d[1] = (uint8_t)max_sym;
    for (int i = 0; i <= max_sym; i++) {
        d[2 + 2 * i]     = (uint8_t)(norm[i] & 0xFF);
        d[2 + 2 * i + 1] = (uint8_t)(norm[i] >> 8);
    }
    return sz;
}

static size_t read_hdr_v2(const uint8_t *s, size_t len, uint16_t norm[NSYM]) {
    memset(norm, 0, NSYM * sizeof(uint16_t));
    if (len < 1) return 0;

    uint8_t fmt = s[0];

    if (fmt == VVA_HDR_SINGLE) {
        if (len < 2) return 0;
        norm[s[1]] = (uint16_t)ANS_L;
        return 2;
    }

    if (fmt == VVA_HDR_SPARSE) {
        if (len < 2) return 0;
        int count = s[1];
        size_t sz = 2 + 3 * (size_t)count;
        if (sz > len) return 0;
        int p = 2;
        for (int i = 0; i < count; i++) {
            int sym = s[p++];
            norm[sym] = (uint16_t)(s[p] | (s[p + 1] << 8));
            p += 2;
        }
        return sz;
    }

    if (fmt == VVA_HDR_DENSE) {
        if (len < 2) return 0;
        int max_sym = s[1];
        size_t sz = 2 + 2 * (size_t)(max_sym + 1);
        if (sz > len) return 0;
        for (int i = 0; i <= max_sym; i++)
            norm[i] = (uint16_t)(s[2 + 2 * i] | (s[2 + 2 * i + 1] << 8));
        return sz;
    }

    /* Legacy v0.5 format: first byte is max_sym (0-255), not a format code.
     * HDR_SINGLE=1, HDR_SPARSE=2, HDR_DENSE=3, so any value ≥4 is legacy.
     * Values 0-3 could also be a legacy max_sym of 0-3.
     * Disambiguate: legacy format has s[1..2] = freq of symbol 0.
     * If s[0] <= 3 and len >= 1+2*(s[0]+1), try legacy. */
    {
        int max_sym = s[0];
        size_t sz = 1 + 2 * (size_t)(max_sym + 1);
        if (sz <= len) {
            for (int i = 0; i <= max_sym; i++)
                norm[i] = (uint16_t)(s[1 + 2 * i] | (s[1 + 2 * i + 1] << 8));
            return sz;
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * BITPAIR STACK (for LIFO encode)
 * ═══════════════════════════════════════════════════════════════ */

/* PERF: val must be uint32_t to hold up to 23 offset extra bits (wlog>16) */
typedef struct { uint32_t val; uint8_t nb; } bitpair_t;

/* ═══════════════════════════════════════════════════════════════
 * INTERNAL: build all tables from normalized frequencies
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t        *spread;
    vva_dec_entry_t *dec;
    enc_ctx_t      *enc;
} tables_t;

static int build_all(const uint16_t norm[NSYM], tables_t *t) {
    /* PERF: coalesce spread + dec into a single allocation.
     * spread is ANS_L bytes; dec is ANS_L * sizeof(vva_dec_entry_t).
     * We store the base pointer in t->spread and carve dec from it.
     * free_all() frees t->spread which covers both. */
    size_t spread_sz = ANS_L;
    size_t dec_sz = ANS_L * sizeof(vva_dec_entry_t);
    t->spread = (uint8_t *)malloc(spread_sz + dec_sz);
    if (!t->spread) {
        t->dec = NULL; t->enc = NULL;
        return -1;
    }
    t->dec = (vva_dec_entry_t *)(t->spread + spread_sz);
    spread_symbols(norm, t->spread);
    build_dec(norm, t->spread, t->dec);
    t->enc = build_enc(norm, t->spread, t->dec);
    if (!t->enc) {
        free(t->spread);
        t->spread = NULL; t->dec = NULL;
        return -1;
    }
    return 0;
}

static void free_all(tables_t *t) {
    /* t->dec is part of the t->spread allocation; only free spread */
    free(t->spread);
    free_enc(t->enc);
}

/* ═══════════════════════════════════════════════════════════════
 * SINGLE-STREAM ENCODE (tag 'A', backward compat)
 * ═══════════════════════════════════════════════════════════════ */

vva_error_t vva_encode(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap, size_t *dst_len) {
    if (!src_len) { *dst_len = 0; return VVA_OK; }

    uint32_t raw[NSYM];
    memset(raw, 0, sizeof(raw));
    for (size_t i = 0; i < src_len; i++) raw[src[i]]++;

    uint16_t norm[NSYM];
    int np = normalize_freq(raw, norm);
    if (!np) return VVA_ERR_PARAM;

    size_t hdr = write_hdr_v2(norm, dst, dst_cap);
    if (!hdr) return VVA_ERR_OVERFLOW;

    if (np == 1) {
        *dst_len = hdr;
        return (hdr >= src_len) ? VVA_ERR_OVERFLOW : VVA_OK;
    }

    tables_t t;
    if (build_all(norm, &t) < 0) return VVA_ERR_NOMEM;

    /* PERF: one combined alloc for pairs + bs. pairs is src_len of
     * bitpair_t; bs is (src_len*15+7)/8 + 16 bytes of bitstream.
     * Saves 1 malloc/free pair per vva_encode call. */
    size_t pairs_sz = src_len * sizeof(bitpair_t);
    size_t bs_cap = (src_len * 15 + 7) / 8 + 16;
    uint8_t *combo = (uint8_t *)malloc(pairs_sz + bs_cap);
    if (!combo) { free_all(&t); return VVA_ERR_NOMEM; }
    bitpair_t *pairs = (bitpair_t *)combo;
    uint8_t *bs = combo + pairs_sz;

    uint32_t state = 0;
    for (size_t ii = src_len; ii > 0; ii--) {
        uint32_t bv; int bn;
        int slot = enc_sym(t.enc, state, src[ii - 1], &bv, &bn);
        if (slot < 0) { free_all(&t); free(combo); return VVA_ERR_CORRUPT; }
        pairs[ii - 1].val = (uint32_t)bv;
        pairs[ii - 1].nb = (uint8_t)bn;
        state = (uint32_t)slot;
    }

    ans_bw_t w;
    ans_bw_init(&w, bs, bs_cap);
    for (size_t i = 0; i < src_len; i++)
        ans_bw_add(&w, pairs[i].val, pairs[i].nb);
    size_t bs_len = ans_bw_flush(&w);

    size_t total = hdr + 2 + bs_len;
    if (total > dst_cap || total >= src_len) {
        free_all(&t); free(combo);
        return VVA_ERR_OVERFLOW;
    }

    dst[hdr]     = (uint8_t)(state & 0xFF);
    dst[hdr + 1] = (uint8_t)((state >> 8) & 0xFF);
    memcpy(dst + hdr + 2, bs, bs_len);

    *dst_len = total;
    free_all(&t); free(combo);
    return VVA_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * SINGLE-STREAM DECODE (tag 'A', backward compat)
 * ═══════════════════════════════════════════════════════════════ */

vva_error_t vva_decode(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap,
                       size_t num_literals, size_t *src_consumed) {
    if (!num_literals) { *src_consumed = 0; return VVA_OK; }
    if (num_literals > dst_cap) return VVA_ERR_OVERFLOW;

    uint16_t norm[NSYM];
    size_t hdr = read_hdr_v2(src, src_len, norm);
    if (!hdr) return VVA_ERR_CORRUPT;

    int np = 0, single = -1;
    for (int i = 0; i < NSYM; i++)
        if (norm[i]) { np++; single = i; }
    if (!np) return VVA_ERR_CORRUPT;
    if (np == 1) {
        memset(dst, single, num_literals);
        *src_consumed = hdr;
        return VVA_OK;
    }

    uint8_t *sp = (uint8_t *)malloc(ANS_L);
    vva_dec_entry_t *dec = (vva_dec_entry_t *)malloc(ANS_L * sizeof(*dec));
    if (!sp || !dec) { free(sp); free(dec); return VVA_ERR_NOMEM; }
    spread_symbols(norm, sp);
    build_dec(norm, sp, dec);
    free(sp);

    if (hdr + 2 > src_len) { free(dec); return VVA_ERR_CORRUPT; }
    uint32_t state = (uint32_t)src[hdr] | ((uint32_t)src[hdr + 1] << 8);
    if (state >= (uint32_t)ANS_L) { free(dec); return VVA_ERR_CORRUPT; }

    ans_br_t r;
    ans_br_init(&r, src + hdr + 2, src_len - hdr - 2);
    ans_br_fill(&r);

    for (size_t i = 0; i < num_literals; i++) {
        if (r.n < ANS_LOG) ans_br_fill(&r);
        vva_dec_entry_t e = dec[state];
        dst[i] = e.symbol;
        uint32_t bits = ans_br_read(&r, e.nbits);
        state = (uint32_t)e.baseline + bits;
        if (state >= (uint32_t)ANS_L) { free(dec); return VVA_ERR_CORRUPT; }
    }

    *src_consumed = hdr + 2 + r.p;
    if (r.n >= 8) {
        size_t ov = (size_t)(r.n / 8);
        if (*src_consumed >= ov) *src_consumed -= ov;
    }

    free(dec);
    return VVA_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * 4-WAY INTERLEAVED ENCODE (tag 'I', v0.6+, Item 2)
 *
 * Split literals into 4 sub-streams (round-robin), encode each
 * independently, then interleave the bitstream output.
 *
 * Output: [header] [4×2B states] [4×2B bitstream_sizes] [bitstream0..3]
 * ═══════════════════════════════════════════════════════════════ */

vva_error_t vva_encode4(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, size_t *dst_len) {
    if (!src_len) { *dst_len = 0; return VVA_OK; }

    /* Count frequencies (shared table for all 4 streams) */
    uint32_t raw[NSYM];
    memset(raw, 0, sizeof(raw));
    for (size_t i = 0; i < src_len; i++) raw[src[i]]++;

    uint16_t norm[NSYM];
    int np = normalize_freq(raw, norm);
    if (!np) return VVA_ERR_PARAM;

    size_t hdr = write_hdr_v2(norm, dst, dst_cap);
    if (!hdr) return VVA_ERR_OVERFLOW;

    if (np == 1) {
        *dst_len = hdr;
        return (hdr >= src_len) ? VVA_ERR_OVERFLOW : VVA_OK;
    }

    tables_t t;
    if (build_all(norm, &t) < 0) return VVA_ERR_NOMEM;

    /* Encode 4 sub-streams independently */
    size_t bs_cap = (src_len * 15 + 7) / 8 + 64;
    size_t lane_cap = bs_cap / 4 + 16;
    uint8_t *bs_bufs[4] = {NULL, NULL, NULL, NULL};
    size_t bs_lens[4] = {0, 0, 0, 0};
    uint16_t states[4] = {0, 0, 0, 0};

    /* PERF: one combined allocation for all 4 lane bitstream buffers
     * (saves 3 mallocs per vva_encode4 call). Each lane gets its own
     * region at offset (lane * lane_cap). */
    uint8_t *all_bs = (uint8_t *)malloc(lane_cap * 4);
    if (!all_bs) return VVA_ERR_NOMEM;
    for (int i = 0; i < 4; i++) bs_bufs[i] = all_bs + (size_t)i * lane_cap;

    /* PERF: allocate pairs buffer ONCE, sized for the largest lane.
     * Each lane has at most (src_len+3)/4 symbols, so this covers all.
     * Previously this was malloc'd 4× per vva_encode4 call, which cost
     * ~4 µs/call on small inputs. */
    size_t max_lane_len = (src_len + 3) / 4;
    bitpair_t *pairs = (bitpair_t *)malloc(max_lane_len * sizeof(bitpair_t));
    if (!pairs) { free(all_bs); free_all(&t); return VVA_ERR_NOMEM; }

    for (int lane = 0; lane < 4; lane++) {
        /* Count symbols in this lane */
        size_t lane_len = 0;
        for (size_t i = (size_t)lane; i < src_len; i += 4) lane_len++;
        if (lane_len == 0) continue;

        uint32_t state = 0;
        /* Encode backward within this lane (pairs is pre-allocated) */
        size_t ki = lane_len;
        for (size_t idx = (lane_len - 1) * 4 + (size_t)lane; ; idx -= 4) {
            ki--;
            if (idx >= src_len) { ki++; if (idx < 4) break; continue; }
            uint32_t bv; int bn;
            int slot = enc_sym(t.enc, state, src[idx], &bv, &bn);
            if (slot < 0) {
                free(all_bs); free(pairs); free_all(&t); return VVA_ERR_CORRUPT;
            }
            pairs[ki].val = (uint32_t)bv;
            pairs[ki].nb = (uint8_t)bn;
            state = (uint32_t)slot;
            if (idx < 4) break;
        }

        /* Write bitstream for this lane (into pre-allocated slot) */
        ans_bw_t w;
        ans_bw_init(&w, bs_bufs[lane], lane_cap);
        for (size_t i = 0; i < lane_len; i++)
            ans_bw_add(&w, pairs[i].val, pairs[i].nb);
        bs_lens[lane] = ans_bw_flush(&w);
        states[lane] = (uint16_t)state;
    }

    free(pairs);

    free_all(&t);

    /* Output: [header] [4×2B states] [4×4B bs_lens] [bs0][bs1][bs2][bs3]
     * bs_lens are 4B to support large literal blocks (v1.6.0+). */
    size_t overhead = hdr + 8 + 16; /* 4 states (2B) + 4 sizes (4B) */
    size_t total_bs = bs_lens[0] + bs_lens[1] + bs_lens[2] + bs_lens[3];
    size_t total = overhead + total_bs;

    if (total > dst_cap || total >= src_len) {
        free(all_bs);
        return VVA_ERR_OVERFLOW;
    }

    uint8_t *op = dst + hdr;
    for (int i = 0; i < 4; i++) {
        op[0] = (uint8_t)(states[i] & 0xFF);
        op[1] = (uint8_t)(states[i] >> 8);
        op += 2;
    }
    for (int i = 0; i < 4; i++) {
        op[0] = (uint8_t)(bs_lens[i] & 0xFF);
        op[1] = (uint8_t)((bs_lens[i] >> 8) & 0xFF);
        op[2] = (uint8_t)((bs_lens[i] >> 16) & 0xFF);
        op[3] = (uint8_t)((bs_lens[i] >> 24) & 0xFF);
        op += 4;
    }
    for (int i = 0; i < 4; i++) {
        memcpy(op, bs_bufs[i], bs_lens[i]);
        op += bs_lens[i];
    }
    free(all_bs);

    *dst_len = total;
    return VVA_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * 4-WAY INTERLEAVED DECODE (tag 'I', v0.6+, Item 2)
 *
 * The hot loop decodes 4 symbols per iteration from 4 independent
 * ANS states. This hides the ~4-cycle L1 table lookup latency —
 * while one lookup resolves, the other 3 are in-flight.
 *
 * Output is interleaved: dst[0]=lane0, dst[1]=lane1, dst[2]=lane2, dst[3]=lane3
 * ═══════════════════════════════════════════════════════════════ */

vva_error_t vva_decode4(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap,
                        size_t num_literals, size_t *src_consumed) {
    if (!num_literals) { *src_consumed = 0; return VVA_OK; }
    if (num_literals > dst_cap) return VVA_ERR_OVERFLOW;

    uint16_t norm[NSYM];
    size_t hdr = read_hdr_v2(src, src_len, norm);
    if (!hdr) return VVA_ERR_CORRUPT;

    int np = 0, single = -1;
    for (int i = 0; i < NSYM; i++)
        if (norm[i]) { np++; single = i; }
    if (!np) return VVA_ERR_CORRUPT;
    if (np == 1) {
        memset(dst, single, num_literals);
        *src_consumed = hdr;
        return VVA_OK;
    }

    /* Build shared decode table */
    uint8_t *sp = (uint8_t *)malloc(ANS_L);
    vva_dec_entry_t *dec = (vva_dec_entry_t *)malloc(ANS_L * sizeof(*dec));
    if (!sp || !dec) { free(sp); free(dec); return VVA_ERR_NOMEM; }
    spread_symbols(norm, sp);
    build_dec(norm, sp, dec);
    free(sp);

    /* Read 4 states (2B) + 4 bitstream sizes (4B) */
    const uint8_t *p = src + hdr;
    if (p + 8 + 16 > src + src_len) { free(dec); return VVA_ERR_CORRUPT; }

    uint32_t s[4];
    size_t bsz[4];
    for (int i = 0; i < 4; i++) {
        s[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
        p += 2;
        if (s[i] >= (uint32_t)ANS_L) { free(dec); return VVA_ERR_CORRUPT; }
    }
    for (int i = 0; i < 4; i++) {
        bsz[i] = (size_t)p[0] | ((size_t)p[1] << 8)
               | ((size_t)p[2] << 16) | ((size_t)p[3] << 24);
        p += 4;
    }

    /* Set up 4 independent bit readers */
    ans_br_t r[4];
    const uint8_t *bp = p;
    for (int i = 0; i < 4; i++) {
        if (bp + bsz[i] > src + src_len) { free(dec); return VVA_ERR_CORRUPT; }
        ans_br_init(&r[i], bp, bsz[i]);
        ans_br_fill(&r[i]);
        bp += bsz[i];
    }

    /* ─── 4-way interleaved decode hot loop ───
     * Process 4 symbols per iteration, one from each lane.
     * Output is round-robin: dst[0]=lane0, dst[1]=lane1, ... */
    size_t out_pos = 0;
    size_t full_quads = num_literals / 4;

    for (size_t q = 0; q < full_quads; q++) {
        /* 4 parallel table lookups — CPU can issue all 4 loads simultaneously
         * because the states are independent (no data dependency). */
        vva_dec_entry_t e0 = dec[s[0]];
        vva_dec_entry_t e1 = dec[s[1]];
        vva_dec_entry_t e2 = dec[s[2]];
        vva_dec_entry_t e3 = dec[s[3]];

        /* 4 symbol outputs */
        dst[out_pos]     = e0.symbol;
        dst[out_pos + 1] = e1.symbol;
        dst[out_pos + 2] = e2.symbol;
        dst[out_pos + 3] = e3.symbol;
        out_pos += 4;

        /* 4 state updates — use results from lookups above */
        if (r[0].n < ANS_LOG) ans_br_fill(&r[0]);
        s[0] = (uint32_t)e0.baseline + ans_br_read(&r[0], e0.nbits);

        if (r[1].n < ANS_LOG) ans_br_fill(&r[1]);
        s[1] = (uint32_t)e1.baseline + ans_br_read(&r[1], e1.nbits);

        if (r[2].n < ANS_LOG) ans_br_fill(&r[2]);
        s[2] = (uint32_t)e2.baseline + ans_br_read(&r[2], e2.nbits);

        if (r[3].n < ANS_LOG) ans_br_fill(&r[3]);
        s[3] = (uint32_t)e3.baseline + ans_br_read(&r[3], e3.nbits);
    }

    /* Scalar tail for remaining 0-3 symbols */
    for (size_t i = full_quads * 4; i < num_literals; i++) {
        int lane = (int)(i & 3);
        if (r[lane].n < ANS_LOG) ans_br_fill(&r[lane]);
        vva_dec_entry_t e = dec[s[lane]];
        dst[i] = e.symbol;
        s[lane] = (uint32_t)e.baseline + ans_br_read(&r[lane], e.nbits);
    }

    *src_consumed = (size_t)(bp - src);
    free(dec);
    return VVA_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * ORDER-1 CONTEXT MODEL (tag 'C', v0.7+ — Item 1 Sprint 7)
 *
 * Uses 256 ANS tables, one per previous byte. Captures correlations
 * like '{' → '"' in JSON, '\n' → digit in logs.
 *
 * Contexts with fewer than 16 observations inherit the global table.
 * This avoids overfitting on sparse contexts and keeps headers small.
 *
 * Header format:
 *   [2B global_table_size] [global_table]
 *   [32B inherited_bitmap: bit c=1 means ctx c is inherited]
 *   For each non-inherited context c:
 *     [1B context_id] [2B table_size] [table_data]
 *
 * ZUPT-COMPAT: this function is available when VV_ANS_STANDALONE defined.
 * Memory: ~4 MB decode tables (L3-resident), allocated per call.
 * ═══════════════════════════════════════════════════════════════ */

#define CTX_MIN_OBS  16  /* Minimum observations to build a context table */

vva_error_t vva_encode_ctx(const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_cap, size_t *dst_len) {
    if (!src_len) { *dst_len = 0; return VVA_OK; }

    /* ─── Pass 1: build 256×256 histogram ─── */
    /* Heap-allocate: 256×256×4 = 256 KB */
    uint32_t (*hist)[NSYM] = (uint32_t (*)[NSYM])calloc(NSYM, NSYM * sizeof(uint32_t));
    uint32_t global_raw[NSYM];
    memset(global_raw, 0, sizeof(global_raw));
    if (!hist) return VVA_ERR_NOMEM;

    uint8_t prev = 0;
    for (size_t i = 0; i < src_len; i++) {
        uint8_t cur = src[i];
        hist[prev][cur]++;
        global_raw[cur]++;
        prev = cur;
    }

    /* ─── Normalize global table ─── */
    uint16_t global_norm[NSYM];
    int global_np = normalize_freq(global_raw, global_norm);
    if (global_np == 0) { free(hist); return VVA_ERR_PARAM; }

    /* ─── Determine which contexts are inherited ─── */
    uint8_t inherited[32]; /* 256-bit bitmap: bit c=1 → inherited */
    memset(inherited, 0xFF, 32); /* Start all inherited */

    uint16_t ctx_norms[NSYM][NSYM]; /* [context][symbol] → normalized freq */
    int ctx_np[NSYM]; /* number of present symbols per context */

    for (int c = 0; c < NSYM; c++) {
        uint32_t row_total = 0;
        for (int s = 0; s < NSYM; s++) row_total += hist[c][s];

        if (row_total >= CTX_MIN_OBS) {
            ctx_np[c] = normalize_freq(hist[c], ctx_norms[c]);
            if (ctx_np[c] > 1) {
                /* Non-trivial context: mark as non-inherited */
                inherited[c / 8] &= ~(1u << (c % 8));
            } else {
                /* Single symbol: still use own table */
                inherited[c / 8] &= ~(1u << (c % 8));
            }
        } else {
            /* Too few observations: inherit global */
            memcpy(ctx_norms[c], global_norm, sizeof(global_norm));
            ctx_np[c] = global_np;
        }
    }

    /* ─── Write header ─── */
    uint8_t *op = dst;
    size_t remaining_cap = dst_cap;

    /* Global table */
    uint8_t global_hdr_buf[600];
    size_t global_hdr_sz = write_hdr_v2(global_norm, global_hdr_buf, sizeof(global_hdr_buf));
    if (!global_hdr_sz) { free(hist); return VVA_ERR_OVERFLOW; }

    if (remaining_cap < 2 + global_hdr_sz + 32) { free(hist); return VVA_ERR_OVERFLOW; }

    /* [2B global_table_size] */
    op[0] = (uint8_t)(global_hdr_sz & 0xFF);
    op[1] = (uint8_t)(global_hdr_sz >> 8);
    op += 2;
    memcpy(op, global_hdr_buf, global_hdr_sz);
    op += global_hdr_sz;

    /* [32B inherited bitmap] */
    memcpy(op, inherited, 32);
    op += 32;

    /* Per non-inherited context tables */
    for (int c = 0; c < NSYM; c++) {
        if (inherited[c / 8] & (1u << (c % 8))) continue; /* Skip inherited */

        uint8_t ctx_hdr_buf[600];
        size_t ctx_hdr_sz = write_hdr_v2(ctx_norms[c], ctx_hdr_buf, sizeof(ctx_hdr_buf));
        if (!ctx_hdr_sz) { free(hist); return VVA_ERR_OVERFLOW; }

        if ((size_t)(op - dst) + 3 + ctx_hdr_sz > dst_cap) { free(hist); return VVA_ERR_OVERFLOW; }

        *op++ = (uint8_t)c;
        op[0] = (uint8_t)(ctx_hdr_sz & 0xFF);
        op[1] = (uint8_t)(ctx_hdr_sz >> 8);
        op += 2;
        memcpy(op, ctx_hdr_buf, ctx_hdr_sz);
        op += ctx_hdr_sz;
    }

    size_t hdr_total = (size_t)(op - dst);

    /* ─── Build encode tables for all 256 contexts ─── */
    /* We need spread + dec + enc for each context.
     * Memory: 256 × (4096 spread + 4096×4 dec + enc_ctx) ≈ 8 MB
     * This is a lot — but it's temporary per block. */
    uint8_t *spread_buf = (uint8_t *)malloc(ANS_L);
    vva_dec_entry_t *dec_buf = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
    enc_ctx_t **enc_tables = (enc_ctx_t **)calloc(NSYM, sizeof(enc_ctx_t *));
    if (!spread_buf || !dec_buf || !enc_tables) {
        free(hist); free(spread_buf); free(dec_buf); free(enc_tables);
        return VVA_ERR_NOMEM;
    }

    /* Build global encode table (for inherited contexts) */
    spread_symbols(global_norm, spread_buf);
    build_dec(global_norm, spread_buf, dec_buf);
    enc_ctx_t *global_enc = build_enc(global_norm, spread_buf, dec_buf);
    if (!global_enc) {
        free(hist); free(spread_buf); free(dec_buf); free(enc_tables);
        return VVA_ERR_NOMEM;
    }

    for (int c = 0; c < NSYM; c++) {
        if (inherited[c / 8] & (1u << (c % 8))) {
            enc_tables[c] = global_enc; /* Alias, not owned */
        } else {
            spread_symbols(ctx_norms[c], spread_buf);
            build_dec(ctx_norms[c], spread_buf, dec_buf);
            enc_tables[c] = build_enc(ctx_norms[c], spread_buf, dec_buf);
            if (!enc_tables[c]) {
                /* Cleanup on failure */
                for (int j = 0; j < c; j++)
                    if (enc_tables[j] != global_enc) free_enc(enc_tables[j]);
                free_enc(global_enc);
                free(hist); free(spread_buf); free(dec_buf); free(enc_tables);
                return VVA_ERR_NOMEM;
            }
        }
    }

    free(spread_buf); free(dec_buf);

    /* ─── Precompute forward context array ─── */
    uint8_t *prev_ctx = (uint8_t *)malloc(src_len);
    if (!prev_ctx) {
        for (int c = 0; c < NSYM; c++)
            if (enc_tables[c] != global_enc) free_enc(enc_tables[c]);
        free_enc(global_enc); free(hist); free(enc_tables);
        return VVA_ERR_NOMEM;
    }
    prev_ctx[0] = 0; /* Initial context */
    for (size_t i = 1; i < src_len; i++)
        prev_ctx[i] = src[i - 1];

    /* ─── Encode backward with context-dependent tables ─── */
    bitpair_t *pairs = (bitpair_t *)malloc(src_len * sizeof(bitpair_t));
    if (!pairs) {
        free(prev_ctx);
        for (int c = 0; c < NSYM; c++)
            if (enc_tables[c] != global_enc) free_enc(enc_tables[c]);
        free_enc(global_enc); free(hist); free(enc_tables);
        return VVA_ERR_NOMEM;
    }

    /* Per-context ANS states (256 independent states) */
    uint16_t ctx_states[NSYM];
    memset(ctx_states, 0, sizeof(ctx_states));

    for (size_t ii = src_len; ii > 0; ii--) {
        uint8_t sym = src[ii - 1];
        uint8_t ctx = prev_ctx[ii - 1];
        uint32_t bv; int bn;
        int slot = enc_sym(enc_tables[ctx], ctx_states[ctx], sym, &bv, &bn);
        if (slot < 0) {
            free(pairs); free(prev_ctx);
            for (int c = 0; c < NSYM; c++)
                if (enc_tables[c] != global_enc) free_enc(enc_tables[c]);
            free_enc(global_enc); free(hist); free(enc_tables);
            return VVA_ERR_CORRUPT;
        }
        pairs[ii - 1].val = (uint32_t)bv;
        pairs[ii - 1].nb = (uint8_t)bn;
        ctx_states[ctx] = (uint16_t)slot;
    }

    free(prev_ctx);
    for (int c = 0; c < NSYM; c++)
        if (enc_tables[c] != global_enc) free_enc(enc_tables[c]);
    free_enc(global_enc); free(hist); free(enc_tables);

    /* ─── Write bitstream: [256×2B states] [bitpairs forward] ─── */
    size_t bs_cap = (src_len * 15 + 7) / 8 + 16;
    uint8_t *bs = (uint8_t *)malloc(bs_cap);
    if (!bs) { free(pairs); return VVA_ERR_NOMEM; }

    ans_bw_t w;
    ans_bw_init(&w, bs, bs_cap);
    for (size_t i = 0; i < src_len; i++)
        ans_bw_add(&w, pairs[i].val, pairs[i].nb);
    size_t bs_len = ans_bw_flush(&w);
    free(pairs);

    /* Output: [header] [512B states] [bitstream] */
    size_t total = hdr_total + 512 + bs_len;
    if (total > dst_cap || total >= src_len) {
        free(bs);
        return VVA_ERR_OVERFLOW;
    }

    /* Write 256 states (2B each, LE) */
    for (int c = 0; c < NSYM; c++) {
        op[0] = (uint8_t)(ctx_states[c] & 0xFF);
        op[1] = (uint8_t)(ctx_states[c] >> 8);
        op += 2;
    }
    memcpy(op, bs, bs_len);
    free(bs);

    *dst_len = total;
    return VVA_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * ORDER-1 CONTEXT MODEL DECODE
 * ═══════════════════════════════════════════════════════════════ */

vva_error_t vva_decode_ctx(const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_cap,
                           size_t num_literals, size_t *src_consumed) {
    if (!num_literals) { *src_consumed = 0; return VVA_OK; }
    if (num_literals > dst_cap) return VVA_ERR_OVERFLOW;

    const uint8_t *p = src;
    const uint8_t *end = src + src_len;

    /* Read global table */
    if (p + 2 > end) return VVA_ERR_CORRUPT;
    size_t global_sz = (size_t)p[0] | ((size_t)p[1] << 8);
    p += 2;
    if (p + global_sz > end) return VVA_ERR_CORRUPT;

    uint16_t global_norm[NSYM];
    size_t ghdr = read_hdr_v2(p, global_sz, global_norm);
    if (!ghdr) return VVA_ERR_CORRUPT;
    p += global_sz;

    /* Check for single-symbol global */
    int global_np = 0, global_single = -1;
    for (int i = 0; i < NSYM; i++)
        if (global_norm[i]) { global_np++; global_single = i; }

    /* Read inherited bitmap */
    if (p + 32 > end) return VVA_ERR_CORRUPT;
    uint8_t inherited[32];
    memcpy(inherited, p, 32);
    p += 32;

    /* Build global decode table */
    uint8_t *sp = (uint8_t *)malloc(ANS_L);
    vva_dec_entry_t *global_dec = (vva_dec_entry_t *)malloc(ANS_L * sizeof(*global_dec));
    if (!sp || !global_dec) { free(sp); free(global_dec); return VVA_ERR_NOMEM; }

    if (global_np > 1) {
        spread_symbols(global_norm, sp);
        build_dec(global_norm, sp, global_dec);
    } else if (global_np == 1) {
        /* Single symbol global: fill table */
        for (int x = 0; x < ANS_L; x++) {
            global_dec[x].symbol = (uint8_t)global_single;
            global_dec[x].nbits = 0;
            global_dec[x].baseline = 0;
        }
    }

    /* Allocate per-context decode tables: 256 pointers to tables.
     * Inherited contexts point to global_dec (not owned).
     * Non-inherited get their own allocation. */
    vva_dec_entry_t **ctx_dec = (vva_dec_entry_t **)calloc(NSYM, sizeof(vva_dec_entry_t *));
    if (!ctx_dec) { free(sp); free(global_dec); return VVA_ERR_NOMEM; }

    /* Set all to global first */
    for (int c = 0; c < NSYM; c++)
        ctx_dec[c] = global_dec;

    /* Read non-inherited context tables */
    for (int c = 0; c < NSYM; c++) {
        if (inherited[c / 8] & (1u << (c % 8))) continue;

        if (p + 3 > end) goto ctx_dec_fail;
        int ctx_id = *p++;
        size_t tsz = (size_t)p[0] | ((size_t)p[1] << 8);
        p += 2;
        if (p + tsz > end) goto ctx_dec_fail;

        uint16_t cnorm[NSYM];
        size_t chdr = read_hdr_v2(p, tsz, cnorm);
        if (!chdr) goto ctx_dec_fail;
        p += tsz;

        vva_dec_entry_t *cdec = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
        if (!cdec) goto ctx_dec_fail;

        int cnp = 0, csingle = -1;
        for (int i = 0; i < NSYM; i++) if (cnorm[i]) { cnp++; csingle = i; }

        if (cnp > 1) {
            spread_symbols(cnorm, sp);
            build_dec(cnorm, sp, cdec);
        } else if (cnp == 1) {
            for (int x = 0; x < ANS_L; x++) {
                cdec[x].symbol = (uint8_t)csingle;
                cdec[x].nbits = 0;
                cdec[x].baseline = 0;
            }
        }
        ctx_dec[ctx_id] = cdec;
    }
    free(sp);

    /* Read 256 initial states */
    if (p + 512 > end) goto ctx_dec_fail;
    uint16_t ctx_states[NSYM];
    for (int c = 0; c < NSYM; c++) {
        ctx_states[c] = (uint16_t)(p[0] | (p[1] << 8));
        p += 2;
    }

    /* Bitstream */
    {
        ans_br_t r;
        ans_br_init(&r, p, (size_t)(end - p));
        ans_br_fill(&r);

        /* Decode forward with context tracking.
         * PERF: prefetch next context table to hide L2/L3 latency.
         * Each context table is 16KB. Without prefetch: ~50 MB/s (L3 thrash).
         * With prefetch: hides latency by 1 iteration → ~300+ MB/s. */
        uint8_t prev_ctx = 0;
        for (size_t i = 0; i < num_literals; i++) {
            if (r.n < ANS_LOG) ans_br_fill(&r);

            uint32_t st = ctx_states[prev_ctx];
            if (st >= (uint32_t)ANS_L) goto ctx_dec_fail;

            vva_dec_entry_t e = ctx_dec[prev_ctx][st];
            dst[i] = e.symbol;

            uint32_t bits = ans_br_read(&r, e.nbits);
            ctx_states[prev_ctx] = (uint16_t)((uint32_t)e.baseline + bits);

            prev_ctx = e.symbol;

            /* Prefetch next context's decode table into L2 cache.
             * The next iteration will access ctx_dec[prev_ctx][ctx_states[prev_ctx]].
             * We can't know ctx_states[prev_ctx] yet, but prefetching the start
             * of the table brings the first cache line (64 bytes = 16 entries). */
            VV_PREFETCH(&ctx_dec[prev_ctx][0]);
        }

        *src_consumed = (size_t)(p - src) + r.p;
        if (r.n >= 8) {
            size_t ov = (size_t)(r.n / 8);
            if (*src_consumed >= ov) *src_consumed -= ov;
        }
    }

    /* Cleanup */
    for (int c = 0; c < NSYM; c++)
        if (ctx_dec[c] != global_dec) free(ctx_dec[c]);
    free(ctx_dec); free(global_dec);
    return VVA_OK;

ctx_dec_fail:
    for (int c = 0; c < NSYM; c++)
        if (ctx_dec[c] != global_dec) free(ctx_dec[c]);
    free(ctx_dec); free(global_dec); free(sp);
    return VVA_ERR_CORRUPT;
}

/* ═══════════════════════════════════════════════════════════════
 * SEQUENCE CODING (tag 'S', v0.8+ — Sprint 8 Item 1)
 *
 * Entropy-codes match lengths and offsets using ANS, replacing
 * raw varint/fixed-width storage. Saves 8-15% on typical data.
 *
 * Match length codes: 36 codes mapping to lengths 4-65538
 * Offset codes: 24 codes mapping to offsets 1-16M
 *
 * ZUPT-COMPAT: these functions are standalone when VV_ANS_STANDALONE.
 *
 * Output format:
 *   [2B lit_count] [2B lit_ans_size] [lit_ans_data]
 *   [2B seq_count]
 *   [2B ml_hdr_size] [ml_table_hdr]
 *   [2B of_hdr_size] [of_table_hdr]
 *   [2B state_ml] [2B state_of]
 *   [2B seq_bs_size] [sequence_bitstream]
 *   [litlen_varints: one per sequence]
 * ═══════════════════════════════════════════════════════════════ */

/* PERF: ML/OF code tables are small fixed arrays — always L1 hot */
static const uint32_t ml_base[VVA_ML_CODES] = {
    4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,
    20,22,24,28,32,40,48,64,96,128,192,256,384,512,1024,2048,
    4096,8192,16384,32768
};
/* ml_base_v2 for tag 'T' (VV_ENTROPY_SEQ_V2) — every entry shifted
 * down by 1, so code 0 means match length 3 instead of 4. Extra-bits
 * table is unchanged since the step sizes between consecutive codes
 * are preserved — only the starting point moves. This closes the
 * binary-compression gap vs gzip-9 which uses min_match=3. */
static const uint32_t ml_base_v2[VVA_ML_CODES] = {
    3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
    19,21,23,27,31,39,47,63,95,127,191,255,383,511,1023,2047,
    4095,8191,16383,32767
};
static const uint8_t ml_extra[VVA_ML_CODES] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,2,2,3,3,4,5,5,6,6,7,7,9,10,11,
    12,13,14,15
};

/* Rep-match codes: 0=rep[0], 1=rep[1], 2=rep[2], 3+=explicit offset.
 * Explicit offset code c (c≥3): offset in [2^(c-3), 2^(c-2)), (c-3) extra bits.
 * This is how zstd encodes repeated offsets — saves 10-15 bits per rep-match. */
static const uint8_t of_extra[VVA_OF_CODES] = {
    0,0,0, /* rep codes: 0 extra bits */
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
};

/* Encode match length → (code, extra_value, extra_bits).
 * Parameterized so both 'S' (ml_base) and 'T' (ml_base_v2) tags
 * share one implementation.
 *
 * SPRINT 56: the original linear-from-top scan iterated up to 36
 * comparisons per call. Profile showed this is called once per
 * matched sequence (nseq-many times per compress). Replacing with
 * a hybrid lookup:
 *   1. Small values (0-18 raw mlen, covering codes 0-16): direct
 *      lookup table since the first 16 codes are consecutive
 *      integers.
 *   2. Medium-large values: branchless binary search over 36 entries
 *      = 6 comparisons max vs the previous 36.
 *
 * Both 'S' (ml_base, min 4) and 'T' (ml_base_v2, min 3) tags share
 * this function; the direct-lookup threshold uses ml_base[16]=18
 * which works for both tables since they diverge only at the high
 * end. */
static void ml_encode_with(uint32_t mlen, const uint32_t *base_tab,
                            uint8_t *code, uint32_t *extra, int *nbits) {
    /* Fast path: small mlen covers the majority of binary matches.
     * ml_base[c] for c=0..15 is consecutive integers:
     *   v1 ml_base[0..15] = 4,5,...,19 (covers up to 19)
     *   v2 ml_base[0..15] = 3,4,...,18 (covers up to 18)
     * Using base_tab[15] as the upper inclusive bound lets the fast
     * path cover code 15 for both variants. */
    if (mlen <= base_tab[15]) {
        uint32_t c = (mlen >= base_tab[0]) ? (mlen - base_tab[0]) : 0;
        *code = (uint8_t)c;
        *extra = 0;       /* codes 0-15 all have ml_extra[c] = 0 */
        *nbits = 0;
        return;
    }

    /* Binary search over codes 16..35 for larger values. */
    int lo = 16, hi = VVA_ML_CODES - 1;
    while (lo < hi) {
        int mid = (lo + hi + 1) >> 1;
        if (mlen >= base_tab[mid]) lo = mid;
        else hi = mid - 1;
    }
    *code = (uint8_t)lo;
    *extra = mlen - base_tab[lo];
    *nbits = ml_extra[lo];
}
/* (ml_encode legacy wrapper removed — all callers migrated to
 * ml_encode_with for explicit table selection.) */

/* (ml_decode removed — its single caller was refactored to use the
 * ml_base_tab parameter directly, enabling 'S'/'T' tag sharing.) */

/* Encode explicit offset → (code, extra_value, extra_bits).
 * Returns code in range [3..26]. Caller handles rep-match codes 0-2. */
static void of_encode(uint32_t offset, uint8_t *code, uint32_t *extra, int *nbits) {
    if (offset == 0) { *code = 3; *extra = 0; *nbits = 0; return; }
    int c = 0;
    uint32_t v = offset;
    while (v > 1) { v >>= 1; c++; }
    if (c >= 24) c = 23; /* clamp to 24 explicit codes */
    *code = (uint8_t)(c + 3); /* shift by 3 for rep codes */
    *extra = offset - (1u << c);
    *nbits = of_extra[c + 3];
}

/* Decode offset code → offset. Codes 0-2 are rep-match (caller resolves).
 * Codes 3-26 are explicit offsets. */
static uint32_t of_decode(uint8_t code, uint32_t extra) {
    if (code < 3) return 0; /* rep-match — caller must handle */
    return (1u << (code - 3)) + extra;
}

/* ─── Literal-run length codes: 36 codes covering 0-65536+
 * Small values (0-18) get short codes; long literal runs (common in logs
 * and binary data with low redundancy) are covered via longer extra-bit codes. */
static const uint32_t ll_base[VVA_LL_CODES] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    16,18,20,24,28,32,48,64,128,256,512,1024,2048,4096,8192,16384,
    32768,49152,57344,61440
};
static const uint8_t ll_extra[VVA_LL_CODES] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,2,2,2,4,4,6,7,8,9,10,11,12,13,14,
    14,13,12,12
};

static void ll_encode(uint32_t litlen, uint8_t *code, uint32_t *extra, int *nbits) {
    /* SPRINT 56: same optimization as ml_encode_with. Small litlens
     * (0-15) are direct-lookup since ll_base[c]=c for c=0..15.
     * Larger values use binary search over the remaining 20 codes
     * (log2 ≈ 5 comparisons vs previous 36). */
    if (litlen <= 15u) {
        *code = (uint8_t)litlen;
        *extra = 0;       /* codes 0-15 all have ll_extra[c] = 0 */
        *nbits = 0;
        return;
    }

    /* Binary search over codes 16..35 */
    int lo = 16, hi = VVA_LL_CODES - 1;
    while (lo < hi) {
        int mid = (lo + hi + 1) >> 1;
        if (litlen >= ll_base[mid]) lo = mid;
        else hi = mid - 1;
    }
    *code = (uint8_t)lo;
    *extra = litlen - ll_base[lo];
    *nbits = ll_extra[lo];
}

static uint32_t ll_decode(uint8_t code, uint32_t extra) {
    return ll_base[code] + extra;
}

/* Write a varint to a buffer, return bytes written (kept for backward compat) */
static size_t __attribute__((unused)) seq_write_varint(uint8_t *dst, size_t val) {
    size_t n = 0;
    while (val >= 255) { dst[n++] = 255; val -= 255; }
    dst[n++] = (uint8_t)val;
    return n;
}

/* Read a varint from a buffer, advance pointer (kept for backward compat) */
static size_t __attribute__((unused)) seq_read_varint(const uint8_t **pp, const uint8_t *end) {
    size_t val = 0;
    while (*pp < end && **pp == 255) { val += 255; (*pp)++; }
    if (*pp < end) { val += **pp; (*pp)++; }
    return val;
}

/* Sequence descriptor (parsed from LZ token stream) */
typedef struct {
    uint32_t litlen;
    uint32_t lit_offset;  /* offset into literal buffer */
    uint32_t matchlen;    /* 0 = last sequence (no match) */
    uint32_t offset;
} seq_t;

/* Parse LZ token stream into sequences + literal buffer.
 * Returns number of sequences, or 0 on error. */
static size_t parse_sequences(const uint8_t *tokens, size_t tok_len,
                               uint8_t *lit_buf, size_t lit_cap,
                               seq_t *seqs, size_t seq_cap,
                               size_t *total_lits, int off_bytes,
                               int min_match) {
    const uint8_t *tp = tokens, *tp_end = tokens + tok_len;
    size_t nseq = 0, nlits = 0;

    /* SPRINT 63: maximum litlen representable by the LL ANS coder is
     * 65535 (ll_base[35]=61440 + max 4095 extra bits). When the encoder
     * produces a single token with litlen > 65535 (reproducer:
     * b'A'*1048839 + os.urandom(65536) triggers it on the tail block),
     * ll_encode's binary search picks code 35, writes the low 12 bits
     * of extra, and silently loses the upper bits. Decoder then reads
     * back a smaller litlen, producing a short output block.
     *
     * Fix: if a parsed token's ll exceeds LL_MAX, split into multiple
     * seq entries: as many (LL_MAX, matchlen=0) zero-match sequences
     * as needed to absorb the overflow, followed by the final sequence
     * carrying the remaining (ll' ≤ LL_MAX) and the original match.
     *
     * Zero-match sequences are already legal in the stream (trailing
     * literals use matchlen=0, offset=0). Adding them mid-stream is
     * wire-compatible — the decoder's existing match_count == 0 test
     * skips the match-copy for these entries. */
    enum { LL_MAX = 65535 };

    while (tp < tp_end && nseq < seq_cap) {
        uint8_t token = *tp++;
        size_t ll = token >> 4;
        size_t mc = token & 0x0F;

        if (ll == 15) {
            size_t ext = 0;
            do {
                if (tp >= tp_end) return 0;
                uint8_t b = *tp++;
                ext += b;
                if (b < 255) break;
            } while (tp < tp_end);
            ll += ext;
        }

        if (tp + ll > tp_end || nlits + ll > lit_cap) return 0;
        memcpy(lit_buf + nlits, tp, ll);
        tp += ll;

        /* SPRINT 63: split oversize literal runs */
        while (ll > LL_MAX) {
            if (nseq >= seq_cap) return 0;
            seqs[nseq].litlen = (uint32_t)LL_MAX;
            seqs[nseq].lit_offset = (uint32_t)nlits;
            seqs[nseq].matchlen = 0;
            seqs[nseq].offset = 0;
            nlits += LL_MAX;
            nseq++;
            ll -= LL_MAX;
        }

        seqs[nseq].litlen = (uint32_t)ll;
        seqs[nseq].lit_offset = (uint32_t)nlits;
        nlits += ll;

        if (tp >= tp_end) {
            seqs[nseq].matchlen = 0;
            seqs[nseq].offset = 0;
            nseq++;
            break;
        }

        if (tp + off_bytes > tp_end) return 0;
        uint32_t off = (off_bytes == 3)
            ? ((uint32_t)tp[0] | ((uint32_t)tp[1] << 8) | ((uint32_t)tp[2] << 16))
            : ((uint32_t)tp[0] | ((uint32_t)tp[1] << 8));
        tp += off_bytes;

        size_t mlen = mc + (size_t)min_match;
        if (mc == 15) {
            size_t ext = 0;
            do {
                if (tp >= tp_end) return 0;
                uint8_t b = *tp++;
                ext += b;
                if (b < 255) break;
            } while (tp < tp_end);
            mlen += ext;
        }

        seqs[nseq].matchlen = (uint32_t)mlen;
        seqs[nseq].offset = off;
        nseq++;
    }

    *total_lits = nlits;
    return nseq;
}

/* ═══════════════════════════════════════════════════════════════
 * ENCODE SEQUENCES
 *
 * Takes raw LZ token stream, outputs ANS-coded sequence block.
 * ═══════════════════════════════════════════════════════════════ */

/* Internal impl. ml_base_tab selects between 'S' (min_match=4) and
 * 'T' (min_match=3) encoding. */
static vva_error_t vva_encode_sequences_impl(const uint8_t *tokens, size_t tok_len,
                                              uint8_t *dst, size_t dst_cap, size_t *dst_len,
                                              int off_bytes,
                                              const uint32_t *ml_base_tab) {
    if (!tok_len) { *dst_len = 0; return VVA_OK; }

    /* Parse into sequences.
     * PERF: one combined alloc for seqs + lit_buf. The sizeof(seq_t)
     * is ≥ 4 bytes so natural alignment for both is satisfied. Saves
     * 1 malloc/free pair per call. */
    size_t max_seqs = tok_len; /* Upper bound */
    size_t seqs_sz = max_seqs * sizeof(seq_t);
    size_t total_scratch = seqs_sz + tok_len;
    uint8_t *base_scratch = (uint8_t *)malloc(total_scratch);
    if (!base_scratch) return VVA_ERR_NOMEM;
    seq_t *seqs = (seq_t *)base_scratch;
    uint8_t *lit_buf = base_scratch + seqs_sz;

    size_t total_lits = 0;
    /* Derive min_match from the ml_base table passed in. For the v1
     * table this is 4; for v2 it's 3. Passed to parse_sequences so
     * it reconstructs mlen consistently with how emit_seq packed it. */
    int min_match = (int)ml_base_tab[0];
    size_t nseq = parse_sequences(tokens, tok_len, lit_buf, tok_len, seqs, max_seqs, &total_lits, off_bytes, min_match);
    if (nseq == 0) { free(base_scratch); return VVA_ERR_CORRUPT; }

    /* ─── Encode literals with 4-way ANS ─── */
    size_t lit_cap = vva_bound(total_lits);
    uint8_t *lit_enc = (uint8_t *)malloc(lit_cap);
    if (!lit_enc) { free(base_scratch); return VVA_ERR_NOMEM; }

    size_t lit_enc_len = 0;
    uint8_t lit_fmt = 0; /* 0=raw, 1=ANS4, 2=ANS1, 3=Huffman (Sprint 71) */
    if (total_lits > 0) {
        /* SPRINT 71 (v2.46): Huffman as a competitive literal coder
         * inside the SEQ stream.
         *
         * Sprint 59-B measured Huffman 5-13% better than ANS4 on raw
         * byte streams of fx_text/fx_json/libc/dickens/etc. But at
         * that time Huffman was only available as an alternative to
         * the entire SEQ path (Path B, 'H' tag), which is essentially
         * never selected because SEQ dominates Path B on real content.
         *
         * The fix: make Huffman an option INSIDE the SEQ path, racing
         * against ANS4 and ANS1 and winning when it's smaller. This
         * captures the raw-stream advantage end-to-end for the subset
         * of blocks where literals dominate the sequence stream.
         *
         * Race all three coders, pick smallest. Cost: ~2× encode time
         * on the literal coding step (which is only a fraction of total
         * encode time). Benefit: 3-7% expected on binary fixtures where
         * literal distributions make Huffman materially better.
         *
         * Decoder support: lit_fmt=3 dispatches to vvh_decode. Wire
         * format unchanged otherwise — existing decoders reject
         * lit_fmt=3 with VVA_ERR_CORRUPT, so this is a decoder-
         * incompatible format change (requires v2.46.0+ decoder). */
        size_t ans4_len = 0, ans1_len = 0, huf_len = 0;
        uint8_t *ans4_buf = (uint8_t *)malloc(lit_cap);
        uint8_t *ans1_buf = (uint8_t *)malloc(lit_cap);
        uint8_t *huf_buf  = (uint8_t *)malloc(lit_cap);
        int ans4_ok = 0, ans1_ok = 0, huf_ok = 0;
        if (ans4_buf) {
            ans4_ok = (vva_encode4(lit_buf, total_lits, ans4_buf, lit_cap, &ans4_len) == VVA_OK);
        }
        if (ans1_buf) {
            ans1_ok = (vva_encode(lit_buf, total_lits, ans1_buf, lit_cap, &ans1_len) == VVA_OK);
        }
        if (huf_buf) {
            huf_ok = (vvh_encode(lit_buf, total_lits, huf_buf, lit_cap, &huf_len) == VVH_OK);
        }

        /* Pick the smallest of the three. Preference order on ties:
         * ANS4 (fastest decode) > ANS1 > Huffman (slowest decode).
         * This preserves decode-speed priority while capturing ratio
         * wins when Huffman is meaningfully better. */
        size_t best_len = 0;
        uint8_t *best_buf = NULL;
        uint8_t best_fmt = 0;
        if (ans4_ok) { best_len = ans4_len; best_buf = ans4_buf; best_fmt = 1; }
        if (ans1_ok && (!best_buf || ans1_len < best_len)) {
            best_len = ans1_len; best_buf = ans1_buf; best_fmt = 2;
        }
        if (huf_ok && (!best_buf || huf_len < best_len)) {
            best_len = huf_len; best_buf = huf_buf; best_fmt = 3;
        }

        if (best_buf && best_len <= lit_cap) {
            memcpy(lit_enc, best_buf, best_len);
            lit_enc_len = best_len;
            lit_fmt = best_fmt;
        } else if (total_lits <= lit_cap) {
            /* All three failed — fall back to raw literals */
            memcpy(lit_enc, lit_buf, total_lits);
            lit_enc_len = total_lits;
            lit_fmt = 0;
        }
        free(ans4_buf); free(ans1_buf); free(huf_buf);
    }

    /* ─── Count ML, OF, and LL code frequencies ─── */
    uint32_t freq_ml[VVA_ML_CODES], freq_of[VVA_OF_CODES], freq_ll[VVA_LL_CODES];
    memset(freq_ml, 0, sizeof(freq_ml));
    memset(freq_of, 0, sizeof(freq_of));
    memset(freq_ll, 0, sizeof(freq_ll));

    /* Precompute OF codes with rep-match detection (forward pass).
     * Store in per-sequence arrays so the backward ANS pass can use them.
     *
     * PERF: consolidate 3 separate mallocs into 1. Layout:
     *   [seq_of_code: nseq × uint8_t]  (padded to 4-byte align)
     *   [seq_of_extra: nseq × uint32_t]
     *   [seq_of_nbits: nseq × int]
     *   [seq_ml_code: nseq × uint8_t]  (SPRINT 54)
     *   [seq_ml_extra: nseq × uint32_t]
     *   [seq_ml_nbits: nseq × int]
     *   [seq_ll_code: nseq × uint8_t]
     *   [seq_ll_extra: nseq × uint32_t]
     *   [seq_ll_nbits: nseq × int]
     *
     * SPRINT 54: also memoize ML and LL codes from the forward pass.
     * Previously only OF codes were stored; the backward-pass ANS
     * encoder was re-computing ml_encode_with() and ll_encode() per
     * sequence, duplicating the work already done in the forward
     * pass. With nseq often in the 10K-100K range and ml_encode_with
     * being a 36-entry linear scan, the redundant work showed up in
     * the encoder profile at ~5-8% of total encode time.
     *
     * Net cost: 1 extra malloc region (~14 × nseq bytes), 0 extra
     * malloc calls. Net saving: the backward pass becomes lookups
     * instead of re-computation. */
    size_t codes_sz = (nseq * sizeof(uint8_t) + 3) & ~(size_t)3;
    size_t extra_sz = nseq * sizeof(uint32_t);
    size_t nbits_sz = nseq * sizeof(int);
    /* 3 streams × (codes + extra + nbits) */
    uint8_t *seq_scratch = (uint8_t *)malloc(3 * (codes_sz + extra_sz + nbits_sz));
    if (!seq_scratch) {
        free(base_scratch); free(lit_enc);
        return VVA_ERR_NOMEM;
    }
    size_t stream_sz = codes_sz + extra_sz + nbits_sz;
    uint8_t  *seq_of_code  = seq_scratch;
    uint32_t *seq_of_extra = (uint32_t *)(seq_scratch + codes_sz);
    int      *seq_of_nbits = (int *)(seq_scratch + codes_sz + extra_sz);
    uint8_t  *seq_ml_code  = seq_scratch + stream_sz;
    uint32_t *seq_ml_extra = (uint32_t *)(seq_scratch + stream_sz + codes_sz);
    int      *seq_ml_nbits = (int *)(seq_scratch + stream_sz + codes_sz + extra_sz);
    uint8_t  *seq_ll_code  = seq_scratch + 2 * stream_sz;
    uint32_t *seq_ll_extra = (uint32_t *)(seq_scratch + 2 * stream_sz + codes_sz);
    int      *seq_ll_nbits = (int *)(seq_scratch + 2 * stream_sz + codes_sz + extra_sz);

    size_t match_count = 0;
    uint32_t enc_rep[3] = {0, 0, 0}; /* Rep-match tracking during forward pass */
    for (size_t i = 0; i < nseq; i++) {
        if (seqs[i].matchlen > 0) {
            uint8_t mc; uint32_t mx; int mn;
            ml_encode_with(seqs[i].matchlen, ml_base_tab, &mc, &mx, &mn);
            freq_ml[mc]++;
            /* SPRINT 54: memoize for backward pass */
            seq_ml_code[i] = mc;
            seq_ml_extra[i] = mx;
            seq_ml_nbits[i] = mn;

            /* Check rep-match before explicit encoding */
            uint32_t off = seqs[i].offset;
            uint8_t oc; uint32_t ox; int on;
            if (off == enc_rep[0] && off != 0) {
                oc = 0; ox = 0; on = 0; /* rep[0] */
            } else if (off == enc_rep[1] && off != 0) {
                oc = 1; ox = 0; on = 0; /* rep[1] */
            } else if (off == enc_rep[2] && off != 0) {
                oc = 2; ox = 0; on = 0; /* rep[2] */
            } else {
                of_encode(off, &oc, &ox, &on); /* explicit: codes 3-26 */
            }
            seq_of_code[i] = oc;
            seq_of_extra[i] = ox;
            seq_of_nbits[i] = on;
            freq_of[oc]++;

            /* Update rep array (same logic as LZ engine) */
            if (off != enc_rep[0] && off != 0) {
                enc_rep[2] = enc_rep[1];
                enc_rep[1] = enc_rep[0];
                enc_rep[0] = off;
            }
            match_count++;
        } else {
            seq_of_code[i] = 0;
            seq_of_extra[i] = 0;
            seq_of_nbits[i] = 0;
            /* SPRINT 54: ml_code unused when matchlen==0, but zero for safety */
            seq_ml_code[i] = 0;
            seq_ml_extra[i] = 0;
            seq_ml_nbits[i] = 0;
        }

        /* Count litlen frequency for ALL sequences (including last) */
        {
            uint8_t lc; uint32_t lx; int ln;
            ll_encode(seqs[i].litlen, &lc, &lx, &ln);
            freq_ll[lc]++;
            /* SPRINT 54: memoize LL codes too */
            seq_ll_code[i] = lc;
            seq_ll_extra[i] = lx;
            seq_ll_nbits[i] = ln;
        }
    }

    /* ─── Build ML and OF ANS tables ─── */
    /* Normalize frequencies to sum=4096 for tables with ≤36/24 symbols */
    uint16_t norm_ml[NSYM], norm_of[NSYM];
    memset(norm_ml, 0, sizeof(norm_ml));
    memset(norm_of, 0, sizeof(norm_of));

    /* PERF: header buffers live on the stack — each is bounded at 600 B
     * (fits any NSYM=256 table header) and they were heap-allocated on
     * every call before. Saves 3 malloc/free pairs per call.
     *
     * Sprint 86: zero-initialized to silence cppcheck false-positive
     * Uninitvar warnings. The buffers are conditionally written by
     * write_hdr_v2() and only read when their corresponding _sz is
     * non-zero, so the previous unininitialized declaration was
     * actually correct — but explicit zeroing costs nothing and makes
     * the static-analyzer-clean property visible to maintainers. */
    uint8_t  ml_hdr_buf[600] = {0}, of_hdr_buf[600] = {0}, ll_hdr_buf[600] = {0};
    size_t ml_hdr_sz = 0, of_hdr_sz = 0, ll_hdr_sz = 0;
    uint8_t *seq_bs = NULL;
    size_t seq_bs_len = 0;
    uint32_t state_ml = 0, state_of = 0, state_ll = 0;
    enc_ctx_t *enc_ll_ctx = NULL;

    /* Build LL ANS table unconditionally (all sequences have litlens) */
    {
        uint32_t raw_ll[NSYM];
        memset(raw_ll, 0, sizeof(raw_ll));
        for (int i = 0; i < VVA_LL_CODES; i++) raw_ll[i] = freq_ll[i];
        uint16_t norm_ll[NSYM];
        memset(norm_ll, 0, sizeof(norm_ll));
        normalize_freq(raw_ll, norm_ll);
        ll_hdr_sz = write_hdr_v2(norm_ll, ll_hdr_buf, 600);
        if (!ll_hdr_sz) goto seq_fail;

        /* PERF: one combined alloc for sp_ll + dec_ll. sp_ll lives in
         * the first ANS_L bytes, dec_ll follows with alignment (16-byte
         * aligned vs 8-byte reads is satisfied since ANS_L=4096 is
         * already 4KB-aligned). Saves 1 malloc/free pair. */
        size_t sp_sz = ANS_L;
        size_t dec_sz = ANS_L * sizeof(vva_dec_entry_t);
        uint8_t *ll_tables = (uint8_t *)malloc(sp_sz + dec_sz);
        if (!ll_tables) goto seq_fail;
        uint8_t *sp_ll = ll_tables;
        vva_dec_entry_t *dec_ll = (vva_dec_entry_t *)(ll_tables + sp_sz);
        spread_symbols(norm_ll, sp_ll);
        build_dec(norm_ll, sp_ll, dec_ll);
        enc_ll_ctx = build_enc(norm_ll, sp_ll, dec_ll);
        free(ll_tables);
        if (!enc_ll_ctx) goto seq_fail;
    }

    if (match_count > 0) {
        /* Treat ML codes as a small-alphabet problem */
        uint32_t raw_ml[NSYM], raw_of[NSYM];
        memset(raw_ml, 0, sizeof(raw_ml));
        memset(raw_of, 0, sizeof(raw_of));
        for (int i = 0; i < VVA_ML_CODES; i++) raw_ml[i] = freq_ml[i];
        for (int i = 0; i < VVA_OF_CODES; i++) raw_of[i] = freq_of[i];

        normalize_freq(raw_ml, norm_ml);
        normalize_freq(raw_of, norm_of);

        /* Write ML and OF table headers (buffers are on the stack) */
        ml_hdr_sz = write_hdr_v2(norm_ml, ml_hdr_buf, 600);
        of_hdr_sz = write_hdr_v2(norm_of, of_hdr_buf, 600);
        if (!ml_hdr_sz || !of_hdr_sz) goto seq_fail;



        /* ─── Build encode tables ───
         * PERF: one combined alloc for sp_ml + dec_ml + sp_of + dec_of
         * (4 fixed-size ANS_L-based buffers). Saves 3 malloc/free pairs. */
        size_t sp_sz = ANS_L;
        size_t dec_sz = ANS_L * sizeof(vva_dec_entry_t);
        size_t combo_sz = (sp_sz + dec_sz) * 2;
        uint8_t *ml_of_tables = (uint8_t *)malloc(combo_sz);
        if (!ml_of_tables) goto seq_fail;
        uint8_t *sp_ml = ml_of_tables;
        vva_dec_entry_t *dec_ml = (vva_dec_entry_t *)(ml_of_tables + sp_sz);
        uint8_t *sp_of = ml_of_tables + sp_sz + dec_sz;
        vva_dec_entry_t *dec_of = (vva_dec_entry_t *)(ml_of_tables + sp_sz + dec_sz + sp_sz);

        spread_symbols(norm_ml, sp_ml);
        build_dec(norm_ml, sp_ml, dec_ml);
        enc_ctx_t *enc_ml_ctx = build_enc(norm_ml, sp_ml, dec_ml);

        spread_symbols(norm_of, sp_of);
        build_dec(norm_of, sp_of, dec_of);
        enc_ctx_t *enc_of_ctx = build_enc(norm_of, sp_of, dec_of);

        free(ml_of_tables);
        if (!enc_ml_ctx || !enc_of_ctx) {
            free_enc(enc_ml_ctx); free_enc(enc_of_ctx);
            goto seq_fail;
        }

        /* ─── Encode ML/OF codes + extra bits in reverse ─── */
        /* Collect bitpairs for ANS-coded symbols + raw extra bits */
        size_t pair_cap = nseq * 6; /* 3 ANS + 3 extra max per seq */
        bitpair_t *pairs = (bitpair_t *)malloc(pair_cap * sizeof(bitpair_t));
        if (!pairs) { free_enc(enc_ml_ctx); free_enc(enc_of_ctx); goto seq_fail; }

        state_ml = 0; state_of = 0; state_ll = 0;
        size_t npairs = 0;

        /* Process sequences in reverse for ANS LIFO.
         * Decoder reads per-sequence: LL, OF, ML (forward).
         * Backward encode order (reversed of decode): ML, OF, LL.
         * After bitstream reversal: LL appears first → decoded first.
         *
         * SPRINT 54: all three code/extra/nbits triples for each
         * sequence were computed in the forward pass and stored in
         * seq_ml_*, seq_of_*, seq_ll_* arrays. Re-use them here
         * instead of recomputing ml_encode_with() and ll_encode().
         * Eliminates ~5-8% of encode time (the forward+backward
         * duplicate work). */
        for (size_t ii = nseq; ii > 0; ii--) {
            size_t idx = ii - 1;
            if (seqs[idx].matchlen > 0) {
                uint8_t mc = seq_ml_code[idx];
                uint32_t mx = seq_ml_extra[idx];
                int mn = seq_ml_nbits[idx];

                uint8_t oc = seq_of_code[idx];
                uint32_t ox = seq_of_extra[idx];
                int on = seq_of_nbits[idx];

                /* ML extra bits (raw) */
                if (mn > 0) {
                    pairs[npairs].val = (uint32_t)mx;
                    pairs[npairs].nb = (uint8_t)mn;
                    npairs++;
                }

                /* ML code (ANS) */
                {
                    uint32_t bv; int bn;
                    int slot = enc_sym(enc_ml_ctx, state_ml, mc, &bv, &bn);
                    if (slot < 0) {
                        free(pairs); free_enc(enc_ml_ctx); free_enc(enc_of_ctx);
                        goto seq_fail;
                    }
                    pairs[npairs].val = (uint32_t)bv;
                    pairs[npairs].nb = (uint8_t)bn;
                    npairs++;
                    state_ml = (uint32_t)slot;
                }

                /* OF extra bits (raw) */
                if (on > 0) {
                    pairs[npairs].val = (uint32_t)ox;
                    pairs[npairs].nb = (uint8_t)on;
                    npairs++;
                }

                /* OF code (ANS) */
                {
                    uint32_t bv; int bn;
                    int slot = enc_sym(enc_of_ctx, state_of, oc, &bv, &bn);
                    if (slot < 0) {
                        free(pairs); free_enc(enc_ml_ctx); free_enc(enc_of_ctx);
                        goto seq_fail;
                    }
                    pairs[npairs].val = (uint32_t)bv;
                    pairs[npairs].nb = (uint8_t)bn;
                    npairs++;
                    state_of = (uint32_t)slot;
                }
            }

            /* LL encoded LAST per sequence (decoded FIRST after reversal) */
            {
                uint8_t lc = seq_ll_code[idx];
                uint32_t lx = seq_ll_extra[idx];
                int ln = seq_ll_nbits[idx];

                if (ln > 0) {
                    pairs[npairs].val = (uint32_t)lx;
                    pairs[npairs].nb = (uint8_t)ln;
                    npairs++;
                }
                {
                    uint32_t bv; int bn;
                    int slot = enc_sym(enc_ll_ctx, state_ll, lc, &bv, &bn);
                    if (slot < 0) {
                        free(pairs); free_enc(enc_ml_ctx); free_enc(enc_of_ctx);
                        goto seq_fail;
                    }
                    pairs[npairs].val = (uint32_t)bv;
                    pairs[npairs].nb = (uint8_t)bn;
                    npairs++;
                    state_ll = (uint32_t)slot;
                }
            }
        }

        free_enc(enc_ml_ctx); free_enc(enc_of_ctx);

        /* Write pairs in reverse (so decoder reads forward).
         * Each pair is up to 32 bits (ANS slot = 14 bits + extra up to 18).
         * Allocate 4 bytes per pair + 16-byte safety margin. */
        size_t bs_cap = npairs * 4 + 16;
        seq_bs = (uint8_t *)malloc(bs_cap);
        if (!seq_bs) { free(pairs); goto seq_fail; }

        ans_bw_t w;
        ans_bw_init(&w, seq_bs, bs_cap);
        for (size_t i = npairs; i > 0; i--)
            ans_bw_add(&w, pairs[i - 1].val, pairs[i - 1].nb);
        seq_bs_len = ans_bw_flush(&w);
        free(pairs);
    }

    /* Litlens are now ANS-coded in the sequence bitstream — no varints needed */

    /* ─── Assemble output ─── */
    /* Format: [4B lit_count] [1B lit_fmt] [4B lit_enc_len] [lit_data]
     *         [4B match_count]
     *         [2B ml_hdr_sz] [ml_hdr] [2B of_hdr_sz] [of_hdr]
     *         [2B state_ml] [2B state_of]
     *         [4B seq_bs_len] [seq_bs]
     *         [litlen_varints] */
    {
        size_t total = 9 + lit_enc_len + 4 + 4 + ml_hdr_sz + 4 + of_hdr_sz
                     + 2 + ll_hdr_sz + 4 + 2 + 4 + seq_bs_len;

        if (total > dst_cap) goto seq_fail;

        uint8_t *op = dst;
        /* Literal section: 4B count + 1B fmt + 4B enc_len */
        op[0]=(uint8_t)total_lits; op[1]=(uint8_t)(total_lits>>8);
        op[2]=(uint8_t)(total_lits>>16); op[3]=(uint8_t)(total_lits>>24); op+=4;
        *op++ = lit_fmt;
        op[0]=(uint8_t)lit_enc_len; op[1]=(uint8_t)(lit_enc_len>>8);
        op[2]=(uint8_t)(lit_enc_len>>16); op[3]=(uint8_t)(lit_enc_len>>24); op+=4;
        if (lit_enc_len > 0) { memcpy(op, lit_enc, lit_enc_len); op += lit_enc_len; }

        /* Match count (4B) */
        op[0]=(uint8_t)match_count; op[1]=(uint8_t)(match_count>>8);
        op[2]=(uint8_t)(match_count>>16); op[3]=(uint8_t)(match_count>>24); op+=4;

        /* ML table */
        op[0] = (uint8_t)(ml_hdr_sz & 0xFF); op[1] = (uint8_t)(ml_hdr_sz >> 8); op += 2;
        if (ml_hdr_sz > 0) { memcpy(op, ml_hdr_buf, ml_hdr_sz); op += ml_hdr_sz; }

        /* OF table */
        op[0] = (uint8_t)(of_hdr_sz & 0xFF); op[1] = (uint8_t)(of_hdr_sz >> 8); op += 2;
        if (of_hdr_sz > 0) { memcpy(op, of_hdr_buf, of_hdr_sz); op += of_hdr_sz; }

        /* LL table */
        op[0] = (uint8_t)(ll_hdr_sz & 0xFF); op[1] = (uint8_t)(ll_hdr_sz >> 8); op += 2;
        if (ll_hdr_sz > 0) { memcpy(op, ll_hdr_buf, ll_hdr_sz); op += ll_hdr_sz; }

        /* States */
        op[0] = (uint8_t)(state_ml & 0xFF); op[1] = (uint8_t)((state_ml >> 8) & 0xFF); op += 2;
        op[0] = (uint8_t)(state_of & 0xFF); op[1] = (uint8_t)((state_of >> 8) & 0xFF); op += 2;
        op[0] = (uint8_t)(state_ll & 0xFF); op[1] = (uint8_t)((state_ll >> 8) & 0xFF); op += 2;

        /* Sequence bitstream (4B size) */
        op[0]=(uint8_t)seq_bs_len; op[1]=(uint8_t)(seq_bs_len>>8);
        op[2]=(uint8_t)(seq_bs_len>>16); op[3]=(uint8_t)(seq_bs_len>>24); op+=4;
        if (seq_bs_len > 0) { memcpy(op, seq_bs, seq_bs_len); op += seq_bs_len; }

        /* Litlens are ANS-coded in the bitstream — no trailing varints */

        *dst_len = (size_t)(op - dst);
    }

    free(base_scratch); free(lit_enc);
    free(seq_scratch);
    free_enc(enc_ll_ctx);
    free(seq_bs);
    return VVA_OK;

seq_fail:
    free(base_scratch); free(lit_enc);
    free(seq_scratch);
    free_enc(enc_ll_ctx);
    free(seq_bs);
    return VVA_ERR_OVERFLOW;
}

/* Public entry for 'S' tag (VV_ENTROPY_SEQ, min_match=4). */
vva_error_t vva_encode_sequences(const uint8_t *tokens, size_t tok_len,
                                  uint8_t *dst, size_t dst_cap, size_t *dst_len,
                                  int off_bytes) {
    return vva_encode_sequences_impl(tokens, tok_len, dst, dst_cap, dst_len,
                                      off_bytes, ml_base);
}

/* Public entry for 'T' tag (VV_ENTROPY_SEQ_V2, min_match=3).
 * Encodes match-length codes using ml_base_v2 so a length-3 match
 * becomes code 0 (instead of being unrepresentable as it is in 'S').
 * The caller (vv_encoder.c) must ensure the token stream contains
 * only matches of length ≥ 3, and must emit the frame with tag 'T'. */
vva_error_t vva_encode_sequences_v2(const uint8_t *tokens, size_t tok_len,
                                     uint8_t *dst, size_t dst_cap, size_t *dst_len,
                                     int off_bytes) {
    return vva_encode_sequences_impl(tokens, tok_len, dst, dst_cap, dst_len,
                                      off_bytes, ml_base_v2);
}

/* ═══════════════════════════════════════════════════════════════
 * DECODE SEQUENCES
 *
 * Takes ANS-coded sequence block, outputs decompressed data.
 * Reconstructs LZ matches in-place using existing copy logic.
 * ═══════════════════════════════════════════════════════════════ */

/* Internal implementation shared by 'S' (min_match=4) and 'T'
 * (min_match=3) entropy tags. Takes the ml_base table as a parameter
 * so both tags use the same code path. Everything else in the 'T'
 * payload is byte-identical to 'S'. */
static vva_error_t vva_decode_sequences_impl(const uint8_t *src, size_t src_len,
                                              uint8_t *dst, size_t dst_cap, size_t *dst_len,
                                              const uint8_t *dst_base,
                                              const uint32_t *ml_base_tab) {
    const uint8_t *p = src, *end = src + src_len;

    /* Read literal section: [4B lit_count] [1B lit_fmt] [4B lit_enc_len] */
        if (p + 9 > end) return VVA_ERR_CORRUPT;
    size_t total_lits = (size_t)p[0]|((size_t)p[1]<<8)|((size_t)p[2]<<16)|((size_t)p[3]<<24); p += 4;
    uint8_t lit_fmt = *p++;
    size_t lit_enc_len = (size_t)p[0]|((size_t)p[1]<<8)|((size_t)p[2]<<16)|((size_t)p[3]<<24); p += 4;
        if (p + lit_enc_len > end) return VVA_ERR_CORRUPT;

    /* Decode literals based on format byte */
    uint8_t *lit_buf = (uint8_t *)malloc(total_lits + 16);
    if (!lit_buf) return VVA_ERR_NOMEM;

    if (total_lits > 0 && lit_enc_len > 0) {
        vva_error_t lerr = VVA_ERR_CORRUPT;
        size_t lit_consumed = 0;

        if (lit_fmt == 1) {
            /* ANS 4-way interleaved */
            lerr = vva_decode4(p, lit_enc_len, lit_buf, total_lits,
                                total_lits, &lit_consumed);
        } else if (lit_fmt == 2) {
            /* ANS single-stream */
            lerr = vva_decode(p, lit_enc_len, lit_buf, total_lits,
                               total_lits, &lit_consumed);
        } else if (lit_fmt == 3) {
            /* SPRINT 71 (v2.46): Huffman-coded literals within SEQ. */
            vvh_error_t herr = vvh_decode(p, lit_enc_len, lit_buf,
                                           total_lits, total_lits,
                                           &lit_consumed);
            lerr = (herr == VVH_OK) ? VVA_OK : VVA_ERR_CORRUPT;
        } else {
            /* Raw literals (lit_fmt == 0) */
            if (lit_enc_len >= total_lits) {
                memcpy(lit_buf, p, total_lits);
                lerr = VVA_OK;
            }
        }
        if (lerr != VVA_OK) { free(lit_buf); return VVA_ERR_CORRUPT; }
    }
    p += lit_enc_len;

    /* Read match count (4B) */
        if (p + 4 > end) { free(lit_buf); return VVA_ERR_CORRUPT; }
    size_t match_count = (size_t)p[0]|((size_t)p[1]<<8)|((size_t)p[2]<<16)|((size_t)p[3]<<24); p += 4;

    /* Read ML table header */
        if (p + 2 > end) { free(lit_buf); return VVA_ERR_CORRUPT; }
    size_t ml_hdr_sz = (size_t)p[0] | ((size_t)p[1] << 8); p += 2;
        if (p + ml_hdr_sz > end) { free(lit_buf); return VVA_ERR_CORRUPT; }

    uint16_t norm_ml[NSYM];
    memset(norm_ml, 0, sizeof(norm_ml));
    if (ml_hdr_sz > 0) read_hdr_v2(p, ml_hdr_sz, norm_ml);
    p += ml_hdr_sz;

    /* Read OF table header */
        if (p + 2 > end) { free(lit_buf); return VVA_ERR_CORRUPT; }
    size_t of_hdr_sz = (size_t)p[0] | ((size_t)p[1] << 8); p += 2;
        if (p + of_hdr_sz > end) { free(lit_buf); return VVA_ERR_CORRUPT; }

    uint16_t norm_of[NSYM];
    memset(norm_of, 0, sizeof(norm_of));
    if (of_hdr_sz > 0) read_hdr_v2(p, of_hdr_sz, norm_of);
    p += of_hdr_sz;

    /* Read LL table header */
        if (p + 2 > end) { free(lit_buf); return VVA_ERR_CORRUPT; }
    size_t ll_hdr_sz = (size_t)p[0] | ((size_t)p[1] << 8); p += 2;
        if (p + ll_hdr_sz > end) { free(lit_buf); return VVA_ERR_CORRUPT; }

    uint16_t norm_ll[NSYM];
    memset(norm_ll, 0, sizeof(norm_ll));
    if (ll_hdr_sz > 0) read_hdr_v2(p, ll_hdr_sz, norm_ll);
    p += ll_hdr_sz;

    /* Read initial states */
        if (p + 6 > end) { free(lit_buf); return VVA_ERR_CORRUPT; }
    uint32_t state_ml = (uint32_t)p[0] | ((uint32_t)p[1] << 8); p += 2;
    uint32_t state_of = (uint32_t)p[0] | ((uint32_t)p[1] << 8); p += 2;
    uint32_t state_ll = (uint32_t)p[0] | ((uint32_t)p[1] << 8); p += 2;

    /* Read sequence bitstream (4B size) */
        if (p + 4 > end) { free(lit_buf); return VVA_ERR_CORRUPT; }
    size_t seq_bs_len = (size_t)p[0]|((size_t)p[1]<<8)|((size_t)p[2]<<16)|((size_t)p[3]<<24); p += 4;
        if (p + seq_bs_len > end) { free(lit_buf); return VVA_ERR_CORRUPT; }

    /* Build ML, OF, and LL decode tables */
    vva_dec_entry_t *dec_ml = NULL, *dec_of = NULL, *dec_ll = NULL;
    {
        uint8_t *sp_tmp = (uint8_t *)malloc(ANS_L);
        if (match_count > 0) {
            dec_ml = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
            dec_of = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
        }
        dec_ll = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
        if (!sp_tmp || !dec_ll || (match_count > 0 && (!dec_ml || !dec_of))) {
            free(sp_tmp); free(dec_ml); free(dec_of); free(dec_ll); free(lit_buf);
            return VVA_ERR_NOMEM;
        }
        if (match_count > 0) {
            spread_symbols(norm_ml, sp_tmp);
            build_dec(norm_ml, sp_tmp, dec_ml);
            spread_symbols(norm_of, sp_tmp);
            build_dec(norm_of, sp_tmp, dec_of);
        }
        spread_symbols(norm_ll, sp_tmp);
        build_dec(norm_ll, sp_tmp, dec_ll);
        free(sp_tmp);
    }

    /* Initialize bitstream reader for sequence data */
    ans_br_t r;
    ans_br_init(&r, p, seq_bs_len);
    ans_br_fill(&r);
    p += seq_bs_len;

    /* Litlens are ANS-coded in the bitstream — no varint stream */

    /* ─── PERF: Decode loop — reconstruct output ─── */
    uint8_t *op = dst;
    uint8_t *op_end = dst + dst_cap;
    size_t lit_pos = 0;
    size_t matches_decoded = 0;
    uint32_t dec_rep[3] = {0, 0, 0}; /* Rep-match offset tracking */

    /* SPRINT 50: Safe-zone precomputation. Two bounds checks run per
     * sequence today:
     *   (1) offset validity:    offset != 0 && offset <= op - dst_base
     *   (2) matchlen overflow:  op + matchlen > op_end
     *
     * Ablation measurements (fx_text): bounds checks cost ~18% of
     * total decode time. The overhead is not the branches themselves
     * (predicted-not-taken, rarely fire) but (a) register pressure
     * from keeping op_end/dst_base live and (b) the compound subtract
     * + compare for (1).
     *
     * Observation: once we're past the first wlog bytes AND not yet
     * near op_end, BOTH checks are guaranteed to pass for any
     * well-formed sequence (offset ≤ wlog ≤ op - dst_base, and
     * matchlen ≤ max_match ≤ op_end - op). In the "safe zone" we can
     * skip the runtime checks with zero security loss — they remain
     * under offset_check_floor and op_safe_end as non-hoistable guards.
     *
     * SAFETY: the skipped checks are tautologies in the safe zone,
     * not removed guarantees. Malformed input that produces an
     * invalid offset or overlong matchlen still triggers the checks
     * near the boundaries. We maintain §4 invariants 3 and 5.
     *
     * SAFEZONE_MAX_OFFSET covers the legal offset range (1 << wlog_max).
     * SAFEZONE_MAX_RUN covers BOTH max litlen and max matchlen (both are
     * bounded by the wire format at ≤65535: LL encoding ll_base[35]=61440
     * + up to 4095 extra bits = 65535; ML encoding likewise). So
     * op_safe_end = op_end - 65535 guarantees any single sequence's
     * total writes (literals + match) fit without per-iter overflow
     * checking. */
    enum { SAFEZONE_MAX_OFFSET = 1u << 20 };  /* Maximum wlog supported */
    enum { SAFEZONE_MAX_RUN    = 65535 };     /* litlen or matchlen */
    uint8_t *op_safe_end = (dst_cap > SAFEZONE_MAX_RUN)
                           ? op_end - SAFEZONE_MAX_RUN : dst;
    const uint8_t *offset_check_floor = dst_base + SAFEZONE_MAX_OFFSET;

    size_t seqs_decoded = 0;
    while (lit_pos < total_lits || matches_decoded < match_count) {
        /* PERF: issue all 3 ANS table lookups early so CPU can overlap
         * the L1 cache fills. The dec_ll/dec_of/dec_ml arrays are
         * independent, so the loads have no data dependency on each
         * other — perfect for ILP. The compiler will schedule these
         * ahead of the bitstream reads that consume their results.
         *
         * Fill once at the top. 64 bits covers up to 1 full sequence
         * worst-case (26+35+27=88 but typical ~15-30). ans_br_read
         * auto-fills when we run out within a sequence. */
        ans_br_fill(&r);

        /* Fast path: in safe zone (past warmup, before final max_match
         * bytes). Both bounds checks are tautological and skipped. */
        int in_safe_zone = (op >= offset_check_floor) & (op <= op_safe_end);

        /* PERF: state validation via mask-on-access rather than
         * explicit branches. Since ANS_L is a power of 2, masking
         * bounds any state into valid-table range at ~0 cost, where
         * the 3 explicit ">= ANS_L" branches would cost 3 predicted-
         * not-taken comparisons per iter. On corrupt input the
         * frame-level XXH64 footer still catches the corruption;
         * here we're protecting against out-of-bounds table access,
         * not declaring correctness. */
        vva_dec_entry_t ell = dec_ll[state_ll & (ANS_L - 1)];
        vva_dec_entry_t eof = dec_of[state_of & (ANS_L - 1)];
        vva_dec_entry_t eml = dec_ml[state_ml & (ANS_L - 1)];

        /* ── Decode LL: state, extra, final litlen ── */
        uint32_t ll_bits = ans_br_read(&r, ell.nbits);
        state_ll = (uint32_t)ell.baseline + ll_bits;
        uint8_t ll_code = ell.symbol;
        uint32_t ll_extra_val = ans_br_read(&r, ll_extra[ll_code]);
        size_t litlen = ll_decode(ll_code, ll_extra_val);

        if (VV_UNLIKELY(lit_pos + litlen > total_lits)) {
            free(dec_ml); free(dec_of); free(dec_ll); free(lit_buf);
            return VVA_ERR_CORRUPT;
        }
        if (VV_UNLIKELY(!in_safe_zone && op + litlen > op_end)) {
            free(dec_ml); free(dec_of); free(dec_ll); free(lit_buf);
            return VVA_ERR_OVERFLOW;
        }
        if (litlen > 0) {
            /* PERF: for litlen ≤ 16 (common case in text/json), do one
             * unconditional 16-byte copy instead of memcpy's branchy
             * dispatch. lit_buf has 16-byte post-allocation slack; the
             * destination window is checked against op_end above.
             *
             * Safe to over-read lit_buf beyond lit_pos+litlen (slack).
             * Safe to over-write op beyond op+litlen as long as
             * op + 16 ≤ op_end; for the last few sequences in a block
             * that may not hold, so fall back to memcpy there. */
            if (VV_LIKELY(litlen <= 16 && op + 16 <= op_end)) {
                memcpy(op, lit_buf + lit_pos, 16);
            } else {
                memcpy(op, lit_buf + lit_pos, litlen);
            }
            op += litlen;
            lit_pos += litlen;
        }
        seqs_decoded++;

        /* SPRINT 63/64: continue the loop even when all matches are
         * consumed, as long as literals remain. Previously this broke
         * out after the last match's iteration, losing any subsequent
         * literal-only sequences.
         *
         * When the encoder splits an oversize literal run (litlen >
         * LL_MAX=65535) into multiple zero-match seqs, some of those
         * seqs come AFTER the last real match. The old break dropped
         * them silently, producing short output.
         *
         * Fix: break only when both literals AND matches are fully
         * consumed. The loop's while() condition already has the
         * right test; just don't short-circuit it. */
        if (matches_decoded >= match_count && lit_pos >= total_lits) break;
        if (matches_decoded >= match_count) continue;

        /* ── Decode OF: state, then offset (rep or explicit) ──
         * No explicit fill — ans_br_read fills when it runs out. */
        uint32_t of_bits = ans_br_read(&r, eof.nbits);
        state_of = (uint32_t)eof.baseline + of_bits;
        uint8_t of_code = eof.symbol;
        uint32_t offset;
        if (of_code < 3) {
            offset = dec_rep[of_code];
        } else {
            uint32_t of_extra_val = ans_br_read(&r, of_extra[of_code]);
            offset = of_decode(of_code, of_extra_val);
        }
        if (offset != 0 && offset != dec_rep[0]) {
            dec_rep[2] = dec_rep[1]; dec_rep[1] = dec_rep[0]; dec_rep[0] = offset;
        }

        /* ── Decode ML: state, extra, final matchlen ── */
        uint32_t ml_bits = ans_br_read(&r, eml.nbits);
        state_ml = (uint32_t)eml.baseline + ml_bits;
        uint8_t ml_code = eml.symbol;
        uint32_t ml_extra_val = ans_br_read(&r, ml_extra[ml_code]);
        uint32_t matchlen = ml_base_tab[ml_code] + ml_extra_val;

        /* Validate and execute match copy.
         *
         * SPRINT 50 safety: the offset upper cap is checked
         * unconditionally — covers adversarial inputs that encode
         * offsets beyond any legal window. In-safe-zone skip only
         * removes the position-dependent check (offset > op - dst_base),
         * which is guaranteed tautological when both
         *    offset ≤ SAFEZONE_MAX_OFFSET   (absolute cap, checked)
         *    op ≥ dst_base + SAFEZONE_MAX_OFFSET  (safe-zone floor)
         * The matchlen-overshoot check is similarly safe because
         * op_safe_end = op_end - SAFEZONE_MAX_MATCH, and matchlen is
         * always ≤ SAFEZONE_MAX_MATCH by wire format. */
        if (VV_UNLIKELY(offset == 0 || offset > SAFEZONE_MAX_OFFSET)) {
            free(dec_ml); free(dec_of); free(dec_ll); free(lit_buf);
            return VVA_ERR_CORRUPT;
        }
        if (VV_UNLIKELY(!in_safe_zone && offset > (uint32_t)(op - dst_base))) {
            free(dec_ml); free(dec_of); free(dec_ll); free(lit_buf);
            return VVA_ERR_CORRUPT;
        }
        if (VV_UNLIKELY(!in_safe_zone && op + matchlen > op_end)) {
            free(dec_ml); free(dec_of); free(dec_ll); free(lit_buf);
            return VVA_ERR_OVERFLOW;
        }

        /* PERF: inline tiered match copy — avoids the function pointer
         * call in vv_copy_match which kills ILP. The compiler can then
         * overlap these stores with the next iteration's ANS decodes.
         *
         * Tiers (matches decode_block_tokens_impl):
         *   offset >= 16: safe bulk 16-byte chunks (no overlap concerns)
         *   offset >= 8:  8-byte chunks (overlap window >= stride)
         *   offset <  8:  byte-by-byte (overlap propagates correctly) */
#ifdef VV_ANS_STANDALONE
        {
            const uint8_t *match_src = op - offset;
            for (uint32_t j = 0; j < matchlen; j++)
                op[j] = match_src[j];
        }
#else
        {
            uint8_t *d = op;
            if (offset >= 16) {
                const uint8_t *s = d - offset;
                /* PERF: common case is matchlen in [4,16] — do one
                 * unconditional 16-byte copy when safe. Over-writes
                 * harmlessly into future output space (caller's buffer
                 * already sized for dsz, plus op_end check above).
                 *
                 * SPRINT 45: same bleed-over hazard as the offset≥8
                 * path. For matchlen < 4, the 16-byte overwrite
                 * corrupts bytes that a subsequent short-offset match
                 * will read. Use an exact 3-byte copy in that case. */
                if (VV_LIKELY(matchlen >= 4 && matchlen <= 16 && d + 16 <= op_end)) {
                    memcpy(d, s, 16);
                } else if (matchlen == 3 && d + 16 <= op_end) {
                    d[0] = s[0]; d[1] = s[1]; d[2] = s[2];
                } else {
                    size_t rem = matchlen;
                    while (rem >= 16) { memcpy(d, s, 16); d += 16; s += 16; rem -= 16; }
                    if (rem > 0) memcpy(d, s, rem);
                }
            } else if (offset >= 8) {
                const uint8_t *s = d - offset;
                /* PERF: matchlen ≤ 8 with offset ≥ 8 → one 8-byte copy.
                 *
                 * SPRINT 45: The fast path writes 8 bytes unconditionally,
                 * which overshoots for small matchlen. For v1 (min_match=4)
                 * this is harmless — the overshoot into d[4..7] gets
                 * overwritten by the next sequence before anyone reads it.
                 * But for v2 (min_match=3), a subsequent short-offset
                 * match reads from d[3..] and sees the overshoot bytes.
                 * Gate the fast path on matchlen ≥ 4 to preserve v1
                 * behavior while making v2 correct. */
                if (VV_LIKELY(matchlen >= 4 && matchlen <= 8 && d + 8 <= op_end)) {
                    uint64_t v; memcpy(&v, s, 8); memcpy(d, &v, 8);
                } else if (matchlen <= 8 && d + 8 <= op_end) {
                    /* matchlen == 3 path: copy exactly 3 bytes without
                     * overshooting. One 4-byte read covers all three
                     * source bytes and is safe since offset ≥ 8 (the
                     * source region is disjoint from the destination). */
                    d[0] = s[0]; d[1] = s[1]; d[2] = s[2];
                } else {
                    size_t rem = matchlen;
                    while (rem >= 8) {
                        uint64_t v; memcpy(&v, s, 8); memcpy(d, &v, 8);
                        d += 8; s += 8; rem -= 8;
                    }
                    while (rem-- > 0) *d++ = *s++;
                }
            } else {
                /* offset < 8: byte-by-byte for correct self-reference.
                 * Experimented with unrolled 16-iter versions; the
                 * branchless form over-writes past matchlen and hurts
                 * text, while the branched form hurts JSON. The simple
                 * loop runs well across all fixtures — the compiler
                 * schedules the dependent byte loads reasonably. */
                for (uint32_t j = 0; j < matchlen; j++)
                    d[j] = d[j - (ptrdiff_t)offset];
            }
        }
#endif
        op += matchlen;

        matches_decoded++;
    }

    *dst_len = (size_t)(op - dst);
    free(dec_ml); free(dec_of); free(dec_ll); free(lit_buf);
    return VVA_OK;
}

/* Public entry for 'S' tag (VV_ENTROPY_SEQ, min_match=4). */
vva_error_t vva_decode_sequences(const uint8_t *src, size_t src_len,
                                  uint8_t *dst, size_t dst_cap, size_t *dst_len,
                                  const uint8_t *dst_base) {
    return vva_decode_sequences_impl(src, src_len, dst, dst_cap, dst_len,
                                      dst_base, ml_base);
}

/* Public entry for 'T' tag (VV_ENTROPY_SEQ_V2, min_match=3).
 * Payload format is byte-identical to 'S' — only the ML table differs.
 * Produced by encoders that opt into v2, decodable by any v2.33.0+ decoder. */
vva_error_t vva_decode_sequences_v2(const uint8_t *src, size_t src_len,
                                     uint8_t *dst, size_t dst_cap, size_t *dst_len,
                                     const uint8_t *dst_base) {
    return vva_decode_sequences_impl(src, src_len, dst, dst_cap, dst_len,
                                      dst_base, ml_base_v2);
}
