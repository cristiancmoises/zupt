/* VaptVupt codec — originally Apache-2.0 by Cristian Cezar Moisés
 * Integrated into Zupt — MIT License
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT AND Apache-2.0
 */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif
/*
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

typedef struct { uint64_t a; int n; uint8_t *b; size_t p, c; } bw_t;

static inline void bw_init(bw_t *w, uint8_t *b, size_t c) {
    w->a = 0; w->n = 0; w->b = b; w->p = 0; w->c = c;
}
static inline void bw_add(bw_t *w, uint32_t v, int nb) {
    if (!nb) return;
    w->a |= (uint64_t)(v & ((1u << nb) - 1)) << w->n;
    w->n += nb;
    while (w->n >= 8 && w->p < w->c) {
        w->b[w->p++] = (uint8_t)w->a;
        w->a >>= 8;
        w->n -= 8;
    }
}
static inline size_t bw_flush(bw_t *w) {
    while (w->n > 0 && w->p < w->c) {
        w->b[w->p++] = (uint8_t)w->a;
        w->a >>= 8;
        w->n -= 8;
    }
    return w->p;
}

typedef struct { uint64_t a; int n; const uint8_t *s; size_t p, l; } br_t;

static inline void br_init(br_t *r, const uint8_t *s, size_t l) {
    r->a = 0; r->n = 0; r->s = s; r->p = 0; r->l = l;
}
static inline void br_fill(br_t *r) {
    while (r->n <= 56 && r->p < r->l) {
        r->a |= (uint64_t)r->s[r->p++] << r->n;
        r->n += 8;
    }
}
static inline uint32_t br_read(br_t *r, int nb) {
    if (!nb) return 0;
    if (r->n < nb) br_fill(r);
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
    t->spread = (uint8_t *)malloc(ANS_L);
    t->dec = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
    if (!t->spread || !t->dec) {
        free(t->spread); free(t->dec);
        t->spread = NULL; t->dec = NULL; t->enc = NULL;
        return -1;
    }
    spread_symbols(norm, t->spread);
    build_dec(norm, t->spread, t->dec);
    t->enc = build_enc(norm, t->spread, t->dec);
    if (!t->enc) {
        free(t->spread); free(t->dec);
        t->spread = NULL; t->dec = NULL;
        return -1;
    }
    return 0;
}

static void free_all(tables_t *t) {
    free(t->spread);
    free(t->dec);
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

    bitpair_t *pairs = (bitpair_t *)malloc(src_len * sizeof(bitpair_t));
    if (!pairs) { free_all(&t); return VVA_ERR_NOMEM; }

    uint32_t state = 0;
    for (size_t ii = src_len; ii > 0; ii--) {
        uint32_t bv; int bn;
        int slot = enc_sym(t.enc, state, src[ii - 1], &bv, &bn);
        if (slot < 0) { free_all(&t); free(pairs); return VVA_ERR_CORRUPT; }
        pairs[ii - 1].val = (uint32_t)bv;
        pairs[ii - 1].nb = (uint8_t)bn;
        state = (uint32_t)slot;
    }

    size_t bs_cap = (src_len * 15 + 7) / 8 + 16;
    uint8_t *bs = (uint8_t *)malloc(bs_cap);
    if (!bs) { free_all(&t); free(pairs); return VVA_ERR_NOMEM; }

    bw_t w;
    bw_init(&w, bs, bs_cap);
    for (size_t i = 0; i < src_len; i++)
        bw_add(&w, pairs[i].val, pairs[i].nb);
    size_t bs_len = bw_flush(&w);

    size_t total = hdr + 2 + bs_len;
    if (total > dst_cap || total >= src_len) {
        free_all(&t); free(pairs); free(bs);
        return VVA_ERR_OVERFLOW;
    }

    dst[hdr]     = (uint8_t)(state & 0xFF);
    dst[hdr + 1] = (uint8_t)((state >> 8) & 0xFF);
    memcpy(dst + hdr + 2, bs, bs_len);

    *dst_len = total;
    free_all(&t); free(pairs); free(bs);
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

    br_t r;
    br_init(&r, src + hdr + 2, src_len - hdr - 2);
    br_fill(&r);

    for (size_t i = 0; i < num_literals; i++) {
        if (r.n < ANS_LOG) br_fill(&r);
        vva_dec_entry_t e = dec[state];
        dst[i] = e.symbol;
        uint32_t bits = br_read(&r, e.nbits);
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
    uint8_t *bs_bufs[4] = {NULL, NULL, NULL, NULL};
    size_t bs_lens[4] = {0, 0, 0, 0};
    uint16_t states[4] = {0, 0, 0, 0};

    for (int lane = 0; lane < 4; lane++) {
        /* Count symbols in this lane */
        size_t lane_len = 0;
        for (size_t i = (size_t)lane; i < src_len; i += 4) lane_len++;
        if (lane_len == 0) continue;

        /* Collect bit-pairs for this lane */
        bitpair_t *pairs = (bitpair_t *)malloc(lane_len * sizeof(bitpair_t));
        if (!pairs) {
            for (int j = 0; j < lane; j++) free(bs_bufs[j]);
            free_all(&t); return VVA_ERR_NOMEM;
        }

        uint32_t state = 0;
        /* Encode backward within this lane */
        size_t ki = lane_len;
        for (size_t idx = (lane_len - 1) * 4 + (size_t)lane; ; idx -= 4) {
            ki--;
            if (idx >= src_len) { ki++; if (idx < 4) break; continue; }
            uint32_t bv; int bn;
            int slot = enc_sym(t.enc, state, src[idx], &bv, &bn);
            if (slot < 0) {
                free(pairs);
                for (int j = 0; j < lane; j++) free(bs_bufs[j]);
                free_all(&t); return VVA_ERR_CORRUPT;
            }
            pairs[ki].val = (uint32_t)bv;
            pairs[ki].nb = (uint8_t)bn;
            state = (uint32_t)slot;
            if (idx < 4) break;
        }

        /* Write bitstream for this lane */
        bs_bufs[lane] = (uint8_t *)malloc(bs_cap / 4 + 16);
        if (!bs_bufs[lane]) {
            free(pairs);
            for (int j = 0; j < lane; j++) free(bs_bufs[j]);
            free_all(&t); return VVA_ERR_NOMEM;
        }

        bw_t w;
        bw_init(&w, bs_bufs[lane], bs_cap / 4 + 16);
        for (size_t i = 0; i < lane_len; i++)
            bw_add(&w, pairs[i].val, pairs[i].nb);
        bs_lens[lane] = bw_flush(&w);
        states[lane] = (uint16_t)state;

        free(pairs);
    }

    free_all(&t);

    /* Output: [header] [4×2B states] [4×2B bs_lens] [bs0][bs1][bs2][bs3] */
    size_t overhead = hdr + 8 + 8; /* 4 states + 4 sizes (2B each) */
    size_t total_bs = bs_lens[0] + bs_lens[1] + bs_lens[2] + bs_lens[3];
    size_t total = overhead + total_bs;

    if (total > dst_cap || total >= src_len) {
        for (int i = 0; i < 4; i++) free(bs_bufs[i]);
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
        op[1] = (uint8_t)(bs_lens[i] >> 8);
        op += 2;
    }
    for (int i = 0; i < 4; i++) {
        memcpy(op, bs_bufs[i], bs_lens[i]);
        op += bs_lens[i];
        free(bs_bufs[i]);
    }

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

    /* Read 4 states + 4 bitstream sizes */
    const uint8_t *p = src + hdr;
    if (p + 16 > src + src_len) { free(dec); return VVA_ERR_CORRUPT; }

    uint32_t s[4];
    size_t bsz[4];
    for (int i = 0; i < 4; i++) {
        s[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
        p += 2;
        if (s[i] >= (uint32_t)ANS_L) { free(dec); return VVA_ERR_CORRUPT; }
    }
    for (int i = 0; i < 4; i++) {
        bsz[i] = (size_t)p[0] | ((size_t)p[1] << 8);
        p += 2;
    }

    /* Set up 4 independent bit readers */
    br_t r[4];
    const uint8_t *bp = p;
    for (int i = 0; i < 4; i++) {
        if (bp + bsz[i] > src + src_len) { free(dec); return VVA_ERR_CORRUPT; }
        br_init(&r[i], bp, bsz[i]);
        br_fill(&r[i]);
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
        if (r[0].n < ANS_LOG) br_fill(&r[0]);
        s[0] = (uint32_t)e0.baseline + br_read(&r[0], e0.nbits);

        if (r[1].n < ANS_LOG) br_fill(&r[1]);
        s[1] = (uint32_t)e1.baseline + br_read(&r[1], e1.nbits);

        if (r[2].n < ANS_LOG) br_fill(&r[2]);
        s[2] = (uint32_t)e2.baseline + br_read(&r[2], e2.nbits);

        if (r[3].n < ANS_LOG) br_fill(&r[3]);
        s[3] = (uint32_t)e3.baseline + br_read(&r[3], e3.nbits);
    }

    /* Scalar tail for remaining 0-3 symbols */
    for (size_t i = full_quads * 4; i < num_literals; i++) {
        int lane = (int)(i & 3);
        if (r[lane].n < ANS_LOG) br_fill(&r[lane]);
        vva_dec_entry_t e = dec[s[lane]];
        dst[i] = e.symbol;
        s[lane] = (uint32_t)e.baseline + br_read(&r[lane], e.nbits);
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

    bw_t w;
    bw_init(&w, bs, bs_cap);
    for (size_t i = 0; i < src_len; i++)
        bw_add(&w, pairs[i].val, pairs[i].nb);
    size_t bs_len = bw_flush(&w);
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
        br_t r;
        br_init(&r, p, (size_t)(end - p));
        br_fill(&r);

        /* Decode forward with context tracking */
        uint8_t prev_ctx = 0;
        for (size_t i = 0; i < num_literals; i++) {
            if (r.n < ANS_LOG) br_fill(&r);

            uint32_t st = ctx_states[prev_ctx];
            if (st >= (uint32_t)ANS_L) goto ctx_dec_fail;

            vva_dec_entry_t e = ctx_dec[prev_ctx][st];
            dst[i] = e.symbol;

            uint32_t bits = br_read(&r, e.nbits);
            ctx_states[prev_ctx] = (uint16_t)((uint32_t)e.baseline + bits);

            prev_ctx = e.symbol; /* Context = previous decoded byte */
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
static const uint8_t ml_extra[VVA_ML_CODES] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,2,2,3,3,4,5,5,6,6,7,7,9,10,11,
    12,13,14,15
};

static const uint8_t of_extra[VVA_OF_CODES] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
};

/* Encode match length → (code, extra_value, extra_bits) */
static void ml_encode(uint32_t mlen, uint8_t *code, uint32_t *extra, int *nbits) {
    for (int c = VVA_ML_CODES - 1; c >= 0; c--) {
        if (mlen >= ml_base[c]) {
            *code = (uint8_t)c;
            *extra = mlen - ml_base[c];
            *nbits = ml_extra[c];
            return;
        }
    }
    *code = 0; *extra = 0; *nbits = 0;
}

/* Decode match length code → length */
static uint32_t ml_decode(uint8_t code, uint32_t extra) {
    return ml_base[code] + extra;
}

/* Encode offset → (code, extra_value, extra_bits) */
static void of_encode(uint32_t offset, uint8_t *code, uint32_t *extra, int *nbits) {
    if (offset == 0) { *code = 0; *extra = 0; *nbits = 0; return; }
    int c = 0;
    uint32_t v = offset;
    while (v > 1) { v >>= 1; c++; }
    if (c >= VVA_OF_CODES) c = VVA_OF_CODES - 1;
    *code = (uint8_t)c;
    *extra = offset - (1u << c);
    *nbits = of_extra[c];
}

/* Decode offset code → offset */
static uint32_t of_decode(uint8_t code, uint32_t extra) {
    return (1u << code) + extra;
}

/* Write a varint to a buffer, return bytes written */
static size_t seq_write_varint(uint8_t *dst, size_t val) {
    size_t n = 0;
    while (val >= 255) { dst[n++] = 255; val -= 255; }
    dst[n++] = (uint8_t)val;
    return n;
}

/* Read a varint from a buffer, advance pointer */
static size_t seq_read_varint(const uint8_t **pp, const uint8_t *end) {
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
                               size_t *total_lits, int off_bytes) {
    const uint8_t *tp = tokens, *tp_end = tokens + tok_len;
    size_t nseq = 0, nlits = 0;

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

        size_t mlen = mc + 4; /* VV_MIN_MATCH = 4 */
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

vva_error_t vva_encode_sequences(const uint8_t *tokens, size_t tok_len,
                                  uint8_t *dst, size_t dst_cap, size_t *dst_len,
                                  int off_bytes) {
    if (!tok_len) { *dst_len = 0; return VVA_OK; }

    /* Parse into sequences */
    size_t max_seqs = tok_len; /* Upper bound */
    seq_t *seqs = (seq_t *)malloc(max_seqs * sizeof(seq_t));
    uint8_t *lit_buf = (uint8_t *)malloc(tok_len);
    if (!seqs || !lit_buf) { free(seqs); free(lit_buf); return VVA_ERR_NOMEM; }

    size_t total_lits = 0;
    size_t nseq = parse_sequences(tokens, tok_len, lit_buf, tok_len, seqs, max_seqs, &total_lits, off_bytes);
    if (nseq == 0) { free(seqs); free(lit_buf); return VVA_ERR_CORRUPT; }

    /* ─── Encode literals with 4-way ANS ─── */
    size_t lit_cap = vva_bound(total_lits);
    uint8_t *lit_enc = (uint8_t *)malloc(lit_cap);
    if (!lit_enc) { free(seqs); free(lit_buf); return VVA_ERR_NOMEM; }

    size_t lit_enc_len = 0;
    uint8_t lit_fmt = 0; /* 0=raw, 1=ANS4, 2=ANS1 */
    if (total_lits > 0) {
        vva_error_t lit_err = vva_encode4(lit_buf, total_lits,
                                           lit_enc, lit_cap, &lit_enc_len);
        if (lit_err == VVA_OK) {
            lit_fmt = 1;
        } else {
            lit_err = vva_encode(lit_buf, total_lits,
                                  lit_enc, lit_cap, &lit_enc_len);
            if (lit_err == VVA_OK) {
                lit_fmt = 2;
            } else {
                /* Store raw */
                if (total_lits <= lit_cap) {
                    memcpy(lit_enc, lit_buf, total_lits);
                    lit_enc_len = total_lits;
                    lit_fmt = 0;
                }
            }
        }
    }

    /* ─── Count ML and OF code frequencies ─── */
    uint32_t freq_ml[VVA_ML_CODES], freq_of[VVA_OF_CODES];
    memset(freq_ml, 0, sizeof(freq_ml));
    memset(freq_of, 0, sizeof(freq_of));

    size_t match_count = 0;
    for (size_t i = 0; i < nseq; i++) {
        if (seqs[i].matchlen > 0) {
            uint8_t mc; uint32_t mx; int mn;
            ml_encode(seqs[i].matchlen, &mc, &mx, &mn);
            freq_ml[mc]++;
            uint8_t oc; uint32_t ox; int on;
            of_encode(seqs[i].offset, &oc, &ox, &on);
            freq_of[oc]++;
            match_count++;
        }
    }

    /* ─── Build ML and OF ANS tables ─── */
    /* Normalize frequencies to sum=4096 for tables with ≤36/24 symbols */
    uint16_t norm_ml[NSYM], norm_of[NSYM];
    memset(norm_ml, 0, sizeof(norm_ml));
    memset(norm_of, 0, sizeof(norm_of));

    uint8_t *ml_hdr_buf = NULL, *of_hdr_buf = NULL;
    size_t ml_hdr_sz = 0, of_hdr_sz = 0;
    uint8_t *seq_bs = NULL;
    size_t seq_bs_len = 0;
    uint8_t *litlen_buf = NULL;
    size_t litlen_len = 0;
    uint32_t state_ml = 0, state_of = 0;

    if (match_count > 0) {
        /* Treat ML codes as a small-alphabet problem */
        uint32_t raw_ml[NSYM], raw_of[NSYM];
        memset(raw_ml, 0, sizeof(raw_ml));
        memset(raw_of, 0, sizeof(raw_of));
        for (int i = 0; i < VVA_ML_CODES; i++) raw_ml[i] = freq_ml[i];
        for (int i = 0; i < VVA_OF_CODES; i++) raw_of[i] = freq_of[i];

        normalize_freq(raw_ml, norm_ml);
        normalize_freq(raw_of, norm_of);

        /* Write ML and OF table headers */
        ml_hdr_buf = (uint8_t *)malloc(600);
        of_hdr_buf = (uint8_t *)malloc(600);
        if (!ml_hdr_buf || !of_hdr_buf) goto seq_fail;

        ml_hdr_sz = write_hdr_v2(norm_ml, ml_hdr_buf, 600);
        of_hdr_sz = write_hdr_v2(norm_of, of_hdr_buf, 600);
        if (!ml_hdr_sz || !of_hdr_sz) goto seq_fail;

        /* ─── Build encode tables ─── */
        uint8_t *sp_ml = (uint8_t *)malloc(ANS_L);
        vva_dec_entry_t *dec_ml = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
        uint8_t *sp_of = (uint8_t *)malloc(ANS_L);
        vva_dec_entry_t *dec_of = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
        if (!sp_ml || !dec_ml || !sp_of || !dec_of) {
            free(sp_ml); free(dec_ml); free(sp_of); free(dec_of);
            goto seq_fail;
        }

        spread_symbols(norm_ml, sp_ml);
        build_dec(norm_ml, sp_ml, dec_ml);
        enc_ctx_t *enc_ml_ctx = build_enc(norm_ml, sp_ml, dec_ml);
        free(sp_ml);

        spread_symbols(norm_of, sp_of);
        build_dec(norm_of, sp_of, dec_of);
        enc_ctx_t *enc_of_ctx = build_enc(norm_of, sp_of, dec_of);
        free(sp_of);

        free(dec_ml); free(dec_of);
        if (!enc_ml_ctx || !enc_of_ctx) {
            free_enc(enc_ml_ctx); free_enc(enc_of_ctx);
            goto seq_fail;
        }

        /* ─── Encode ML/OF codes + extra bits in reverse ─── */
        /* Collect bitpairs for ANS-coded symbols + raw extra bits */
        size_t pair_cap = match_count * 4; /* 2 ANS + 2 extra max */
        bitpair_t *pairs = (bitpair_t *)malloc(pair_cap * sizeof(bitpair_t));
        if (!pairs) { free_enc(enc_ml_ctx); free_enc(enc_of_ctx); goto seq_fail; }

        state_ml = 0; state_of = 0;
        size_t npairs = 0;

        /* Process matches in reverse for ANS LIFO */
        for (size_t ii = nseq; ii > 0; ii--) {
            if (seqs[ii - 1].matchlen == 0) continue;

            uint8_t mc, oc;
            uint32_t mx, ox;
            int mn, on;
            ml_encode(seqs[ii - 1].matchlen, &mc, &mx, &mn);
            of_encode(seqs[ii - 1].offset, &oc, &ox, &on);

            /* Encode in this order (reversed): ml_code, ml_extra, of_code, of_extra
             * Decoder reads: of_extra, of_code, ml_extra, ml_code */

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
                /* Handle >16 extra bits for large offsets */
                if (on > 16) {
                    /* Split: already wrote low 16 bits, now high bits */
                    /* Actually our bw_add handles up to ~30 bits, so OK */
                }
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

        free_enc(enc_ml_ctx); free_enc(enc_of_ctx);

        /* Write pairs in reverse (so decoder reads forward) */
        size_t bs_cap = npairs * 2 + 16;
        seq_bs = (uint8_t *)malloc(bs_cap);
        if (!seq_bs) { free(pairs); goto seq_fail; }

        bw_t w;
        bw_init(&w, seq_bs, bs_cap);
        for (size_t i = npairs; i > 0; i--)
            bw_add(&w, pairs[i - 1].val, pairs[i - 1].nb);
        seq_bs_len = bw_flush(&w);
        free(pairs);
    }

    /* ─── Encode litlen varints ─── */
    litlen_buf = (uint8_t *)malloc(nseq * 5 + 1);
    if (!litlen_buf) goto seq_fail;
    {
        size_t pos = 0;
        for (size_t i = 0; i < nseq; i++)
            pos += seq_write_varint(litlen_buf + pos, seqs[i].litlen);
        litlen_len = pos;
    }

    /* ─── Assemble output ─── */
    /* Format: [4B lit_count] [1B lit_fmt] [4B lit_enc_len] [lit_data]
     *         [4B match_count]
     *         [2B ml_hdr_sz] [ml_hdr] [2B of_hdr_sz] [of_hdr]
     *         [2B state_ml] [2B state_of]
     *         [4B seq_bs_len] [seq_bs]
     *         [litlen_varints] */
    {
        size_t total = 9 + lit_enc_len + 4 + 4 + ml_hdr_sz + 4 + of_hdr_sz
                     + 4 + 4 + seq_bs_len + litlen_len;

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

        /* States */
        op[0] = (uint8_t)(state_ml & 0xFF); op[1] = (uint8_t)((state_ml >> 8) & 0xFF); op += 2;
        op[0] = (uint8_t)(state_of & 0xFF); op[1] = (uint8_t)((state_of >> 8) & 0xFF); op += 2;

        /* Sequence bitstream (4B size) */
        op[0]=(uint8_t)seq_bs_len; op[1]=(uint8_t)(seq_bs_len>>8);
        op[2]=(uint8_t)(seq_bs_len>>16); op[3]=(uint8_t)(seq_bs_len>>24); op+=4;
        if (seq_bs_len > 0) { memcpy(op, seq_bs, seq_bs_len); op += seq_bs_len; }

        /* Litlen varints */
        memcpy(op, litlen_buf, litlen_len); op += litlen_len;

        *dst_len = (size_t)(op - dst);
    }

    free(seqs); free(lit_buf); free(lit_enc);
    free(ml_hdr_buf); free(of_hdr_buf); free(seq_bs); free(litlen_buf);
    return VVA_OK;

seq_fail:
    free(seqs); free(lit_buf); free(lit_enc);
    free(ml_hdr_buf); free(of_hdr_buf); free(seq_bs); free(litlen_buf);
    return VVA_ERR_OVERFLOW;
}

/* ═══════════════════════════════════════════════════════════════
 * DECODE SEQUENCES
 *
 * Takes ANS-coded sequence block, outputs decompressed data.
 * Reconstructs LZ matches in-place using existing copy logic.
 * ═══════════════════════════════════════════════════════════════ */

vva_error_t vva_decode_sequences(const uint8_t *src, size_t src_len,
                                  uint8_t *dst, size_t dst_cap, size_t *dst_len) {
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

    /* Read initial states */
    if (p + 4 > end) { free(lit_buf); return VVA_ERR_CORRUPT; }
    uint32_t state_ml = (uint32_t)p[0] | ((uint32_t)p[1] << 8); p += 2;
    uint32_t state_of = (uint32_t)p[0] | ((uint32_t)p[1] << 8); p += 2;

    /* Read sequence bitstream (4B size) */
    if (p + 4 > end) { free(lit_buf); return VVA_ERR_CORRUPT; }
    size_t seq_bs_len = (size_t)p[0]|((size_t)p[1]<<8)|((size_t)p[2]<<16)|((size_t)p[3]<<24); p += 4;
    if (p + seq_bs_len > end) { free(lit_buf); return VVA_ERR_CORRUPT; }

    /* Build ML and OF decode tables */
    vva_dec_entry_t *dec_ml = NULL, *dec_of = NULL;
    if (match_count > 0) {
        uint8_t *sp_tmp = (uint8_t *)malloc(ANS_L);
        dec_ml = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
        dec_of = (vva_dec_entry_t *)malloc(ANS_L * sizeof(vva_dec_entry_t));
        if (!sp_tmp || !dec_ml || !dec_of) {
            free(sp_tmp); free(dec_ml); free(dec_of); free(lit_buf);
            return VVA_ERR_NOMEM;
        }
        spread_symbols(norm_ml, sp_tmp);
        build_dec(norm_ml, sp_tmp, dec_ml);
        spread_symbols(norm_of, sp_tmp);
        build_dec(norm_of, sp_tmp, dec_of);
        free(sp_tmp);
    }

    /* Initialize bitstream reader for sequence data */
    br_t r;
    br_init(&r, p, seq_bs_len);
    br_fill(&r);
    p += seq_bs_len;

    /* Litlen varint stream starts at p */
    const uint8_t *ll_p = p;

    /* ─── PERF: Decode loop — reconstruct output ─── */
    uint8_t *op = dst;
    uint8_t *op_end = dst + dst_cap;
    size_t lit_pos = 0;
    size_t matches_decoded = 0;

    /* We don't know exact nseq, but we have match_count matches + possibly
     * one final literal-only sequence. Decode until all literals consumed
     * and all matches decoded. */
    while (lit_pos < total_lits || matches_decoded < match_count) {
        /* Read litlen from varint stream */
        size_t litlen = seq_read_varint(&ll_p, end);

        /* Copy literals from decoded literal buffer */
        if (lit_pos + litlen > total_lits) { free(dec_ml); free(dec_of); free(lit_buf); return VVA_ERR_CORRUPT; }
        if (op + litlen > op_end) { free(dec_ml); free(dec_of); free(lit_buf); return VVA_ERR_OVERFLOW; }
        if (litlen > 0) {
            memcpy(op, lit_buf + lit_pos, litlen);
            op += litlen;
            lit_pos += litlen;
        }

        /* If all matches decoded, this was the last literal-only sequence */
        if (matches_decoded >= match_count) break;

        /* Decode offset */
        if (r.n < ANS_LOG) br_fill(&r);
        if (state_of >= (uint32_t)ANS_L) { free(dec_ml); free(dec_of); free(lit_buf); return VVA_ERR_CORRUPT; }
        vva_dec_entry_t eof = dec_of[state_of];
        uint32_t of_bits = br_read(&r, eof.nbits);
        state_of = (uint32_t)eof.baseline + of_bits;

        /* Read offset extra bits */
        uint8_t of_code = eof.symbol;
        uint32_t of_extra_val = 0;
        if (of_code < VVA_OF_CODES && of_extra[of_code] > 0) {
            of_extra_val = br_read(&r, of_extra[of_code]);
        }
        uint32_t offset = of_decode(of_code, of_extra_val);

        /* Decode match length */
        if (r.n < ANS_LOG) br_fill(&r);
        if (state_ml >= (uint32_t)ANS_L) { free(dec_ml); free(dec_of); free(lit_buf); return VVA_ERR_CORRUPT; }
        vva_dec_entry_t eml = dec_ml[state_ml];
        uint32_t ml_bits = br_read(&r, eml.nbits);
        state_ml = (uint32_t)eml.baseline + ml_bits;

        /* Read matchlen extra bits */
        uint8_t ml_code = eml.symbol;
        uint32_t ml_extra_val = 0;
        if (ml_code < VVA_ML_CODES && ml_extra[ml_code] > 0) {
            ml_extra_val = br_read(&r, ml_extra[ml_code]);
        }
        uint32_t matchlen = ml_decode(ml_code, ml_extra_val);

        /* Validate and execute match copy */
        if (offset == 0 || offset > (uint32_t)(op - dst)) {
            free(dec_ml); free(dec_of); free(lit_buf);
            return VVA_ERR_CORRUPT;
        }
        if (op + matchlen > op_end) {
            free(dec_ml); free(dec_of); free(lit_buf);
            return VVA_ERR_OVERFLOW;
        }

        /* PERF: match copy — use SIMD tiered copy when available.
         * ZUPT-COMPAT: standalone path uses scalar copy for portability. */
#ifdef VV_ANS_STANDALONE
        {
            const uint8_t *match_src = op - offset;
            for (uint32_t j = 0; j < matchlen; j++)
                op[j] = match_src[j];
        }
#else
        vv_copy_match(op, offset, matchlen);
#endif
        op += matchlen;

        matches_decoded++;
    }

    *dst_len = (size_t)(op - dst);
    free(dec_ml); free(dec_of); free(lit_buf);
    return VVA_OK;
}
