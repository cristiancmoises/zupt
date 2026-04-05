/* VaptVupt codec — originally Apache-2.0 by Cristian Cezar Moisés
 * Integrated into Zupt — MIT License
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT AND Apache-2.0
 */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif

/*
 * VaptVupt — Canonical Huffman Codec Implementation
 *
 * Performance targets (x86-64, gcc -O2):
 *   Encode: ≥ 150 MB/s (bottleneck: bit packing, 1 symbol per ~4 cycles)
 *   Decode: ≥ 800 MB/s (bottleneck: table lookup + refill, 1 symbol per ~5 cycles)
 *
 * If decode falls short of 800 MB/s, the cause is likely the refill frequency.
 * Fix: unroll the decode loop 4× and refill once per 4 symbols (amortize refill).
 *
 * Algorithm:
 *   1. Count symbol frequencies
 *   2. Build Huffman tree (two-queue merge, O(n) after sort)
 *   3. Extract code lengths, limit to 15 bits
 *   4. Assign canonical codes (sorted by length then symbol)
 *   5. Encode: LSB-first bitstream with 64-bit accumulator
 *   6. Decode: 12-bit lookup table (16 KB, L1-resident)
 *
 * Header format (on-disk):
 *   [1B max_symbol]   — highest symbol index with nonzero code length (0-255)
 *   [(max_symbol+2)/2 bytes]  — code lengths packed as nibble pairs:
 *       byte[i] = (lengths[2*i] << 4) | lengths[2*i+1]
 *   Total header: 1 + ceil((max_symbol+1)/2) bytes (1-129 bytes)
 */

#include "vv_huffman.h"
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════
 * BITSTREAM WRITER (LSB-first, 64-bit accumulator)
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t bits;
    int      nbits;
    uint8_t *dst;
    size_t   pos;
    size_t   cap;
} bw_t;

static inline void bw_init(bw_t *w, uint8_t *dst, size_t cap) {
    w->bits = 0; w->nbits = 0; w->dst = dst; w->pos = 0; w->cap = cap;
}

/* Add up to 16 bits. Flushes full bytes automatically. */
static inline void bw_add(bw_t *w, uint32_t val, int n) {
    w->bits |= (uint64_t)(val & ((1u << n) - 1)) << w->nbits;
    w->nbits += n;
    /* Flush complete bytes */
    while (w->nbits >= 8 && w->pos < w->cap) {
        w->dst[w->pos++] = (uint8_t)(w->bits);
        w->bits >>= 8;
        w->nbits -= 8;
    }
}

static inline size_t bw_flush(bw_t *w) {
    while (w->nbits > 0 && w->pos < w->cap) {
        w->dst[w->pos++] = (uint8_t)(w->bits);
        w->bits >>= 8;
        w->nbits -= 8;
    }
    return w->pos;
}

/* ═══════════════════════════════════════════════════════════════
 * BITSTREAM READER (LSB-first, 64-bit accumulator)
 *
 * PERFORMANCE-CRITICAL: this is the decode hot path.
 * The refill reads 8 bytes at a time when possible.
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t       bits;
    int            nbits;
    const uint8_t *src;
    size_t         pos;
    size_t         len;
} br_t;

static inline void br_init(br_t *r, const uint8_t *src, size_t len) {
    r->bits = 0; r->nbits = 0; r->src = src; r->pos = 0; r->len = len;
}

/* Refill: load bytes until accumulator is full (≥56 bits) */
static inline void br_refill(br_t *r) {
    while (r->nbits <= 56 && r->pos < r->len) {
        r->bits |= (uint64_t)r->src[r->pos++] << r->nbits;
        r->nbits += 8;
    }
}

static inline uint32_t br_peek(const br_t *r, int n) {
    return (uint32_t)(r->bits & ((1ULL << n) - 1));
}

static inline void br_consume(br_t *r, int n) {
    r->bits >>= n;
    r->nbits -= n;
}

/* ═══════════════════════════════════════════════════════════════
 * REVERSE BITS (for LSB-first canonical code storage)
 * ═══════════════════════════════════════════════════════════════ */

static inline uint16_t reverse_bits(uint16_t code, int len) {
    uint16_t rev = 0;
    for (int i = 0; i < len; i++) {
        rev = (uint16_t)((rev << 1) | (code & 1));
        code >>= 1;
    }
    return rev;
}

/* ═══════════════════════════════════════════════════════════════
 * BUILD HUFFMAN CODE LENGTHS FROM FREQUENCIES
 *
 * Two-queue merge algorithm (O(n) after sorting):
 *   1. Sort non-zero symbols by frequency (ascending)
 *   2. Merge two cheapest nodes repeatedly using two queues
 *      (leaf queue + internal node queue)
 *   3. Extract depths via parent pointers
 *   4. Limit max depth to VVH_MAX_CODE_LEN (15)
 * ═══════════════════════════════════════════════════════════════ */

static void build_code_lengths(const uint32_t freq[VVH_SYMBOLS],
                                uint8_t lengths[VVH_SYMBOLS]) {
    /* Collect non-zero symbols, sort by frequency */
    int sym_idx[VVH_SYMBOLS];
    uint32_t sym_freq[VVH_SYMBOLS];
    int n = 0;

    memset(lengths, 0, VVH_SYMBOLS);
    for (int i = 0; i < VVH_SYMBOLS; i++) {
        if (freq[i] > 0) {
            sym_idx[n] = i;
            sym_freq[n] = freq[i];
            n++;
        }
    }

    if (n == 0) return;
    if (n == 1) { lengths[sym_idx[0]] = 1; return; }
    if (n == 2) { lengths[sym_idx[0]] = 1; lengths[sym_idx[1]] = 1; return; }

    /* Insertion sort by frequency ascending (n ≤ 256, fast enough) */
    for (int i = 1; i < n; i++) {
        uint32_t tf = sym_freq[i];
        int ts = sym_idx[i];
        int j = i - 1;
        while (j >= 0 && sym_freq[j] > tf) {
            sym_freq[j + 1] = sym_freq[j];
            sym_idx[j + 1] = sym_idx[j];
            j--;
        }
        sym_freq[j + 1] = tf;
        sym_idx[j + 1] = ts;
    }

    /* Heap-allocate tree workspace: 2n-1 nodes (n >= 3, so total >= 5) */
    size_t total = 2u * (unsigned)n - 1u;
    uint32_t *nf = (uint32_t *)calloc(total, sizeof(uint32_t));
    int16_t *par = (int16_t *)malloc(total * sizeof(int16_t));
    if (!nf || !par) { free(nf); free(par); return; }

    /* Initialize leaf nodes */
    for (int i = 0; i < n; i++) {
        nf[i] = sym_freq[i];
        par[i] = -1;
    }
    for (size_t i = (size_t)n; i < total; i++) {
        nf[i] = 0;
        par[i] = -1;
    }

    /* Two-queue merge */
    int lq = 0;        /* Leaf queue read pointer */
    int iq = n;         /* Internal queue read pointer */
    int next = n;       /* Next internal node to create */

    for (int m = 0; m < n - 1; m++) {
        uint32_t cost = 0;
        for (int pick = 0; pick < 2; pick++) {
            int use_leaf = (lq < n) && (iq >= next || nf[lq] <= nf[iq]);
            if (use_leaf) {
                cost += nf[lq];
                par[lq] = (int16_t)next;
                lq++;
            } else {
                cost += nf[iq];
                par[iq] = (int16_t)next;
                iq++;
            }
        }
        nf[next] = cost;
        par[next] = -1;
        next++;
    }

    /* Compute depths */
    uint8_t *dep = (uint8_t *)calloc(total, 1);
    if (!dep) { free(nf); free(par); return; }
    dep[total - 1] = 0;
    for (int i = (int)total - 2; i >= 0; i--)
        dep[i] = dep[par[i]] + 1;

    /* Extract leaf depths */
    for (int i = 0; i < n; i++)
        lengths[sym_idx[i]] = dep[i];

    free(nf); free(par); free(dep);

    /* ─── Depth limiting to VVH_MAX_CODE_LEN ─── */
    int max_d = 0;
    for (int i = 0; i < VVH_SYMBOLS; i++)
        if (lengths[i] > max_d) max_d = lengths[i];
    if (max_d <= VVH_MAX_CODE_LEN) return;

    /* Count symbols per depth */
    int bl_count[32];
    memset(bl_count, 0, sizeof(bl_count));
    for (int i = 0; i < VVH_SYMBOLS; i++)
        if (lengths[i] > 0) bl_count[lengths[i]]++;

    /* Cap depths > 15 to 15 */
    for (int d = VVH_MAX_CODE_LEN + 1; d < 32; d++) {
        bl_count[VVH_MAX_CODE_LEN] += bl_count[d];
        bl_count[d] = 0;
    }

    /* Fix Kraft inequality: sum(bl_count[d] * 2^(15-d)) must ≤ 2^15 */
    for (;;) {
        uint32_t kraft = 0;
        for (int d = 1; d <= VVH_MAX_CODE_LEN; d++)
            kraft += (uint32_t)bl_count[d] << (VVH_MAX_CODE_LEN - d);
        if (kraft <= (1u << VVH_MAX_CODE_LEN)) break;
        /* Move one symbol from shallowest level deeper */
        for (int d = VVH_MAX_CODE_LEN - 1; d >= 1; d--) {
            if (bl_count[d] > 0) {
                bl_count[d]--;
                bl_count[d + 1]++;
                break;
            }
        }
    }

    /* Reassign lengths: sort non-zero symbols by (current_length asc, symbol asc)
     * then assign from the bl_count distribution shortest-first */
    typedef struct { uint8_t len; uint8_t sym; } ls_t;
    ls_t sorted[VVH_SYMBOLS];
    int ns = 0;
    for (int i = 0; i < VVH_SYMBOLS; i++)
        if (lengths[i] > 0) {
            sorted[ns].len = lengths[i] > VVH_MAX_CODE_LEN
                           ? VVH_MAX_CODE_LEN : lengths[i];
            sorted[ns].sym = (uint8_t)i;
            ns++;
        }
    /* Sort by len ascending, then sym ascending */
    for (int i = 1; i < ns; i++) {
        ls_t tmp = sorted[i];
        int j = i - 1;
        while (j >= 0 && (sorted[j].len > tmp.len ||
              (sorted[j].len == tmp.len && sorted[j].sym > tmp.sym))) {
            sorted[j + 1] = sorted[j]; j--;
        }
        sorted[j + 1] = tmp;
    }
    /* Assign from distribution */
    int si = 0;
    for (int d = 1; d <= VVH_MAX_CODE_LEN && si < ns; d++)
        for (int c = 0; c < bl_count[d] && si < ns; c++)
            lengths[sorted[si++].sym] = (uint8_t)d;
}

/* ═══════════════════════════════════════════════════════════════
 * CANONICAL CODE ASSIGNMENT
 * ═══════════════════════════════════════════════════════════════ */

static void assign_canonical_codes(const uint8_t lengths[VVH_SYMBOLS],
                                    uint16_t codes[VVH_SYMBOLS]) {
    /* Count symbols at each length */
    int bl_count[VVH_MAX_CODE_LEN + 1];
    memset(bl_count, 0, sizeof(bl_count));
    for (int i = 0; i < VVH_SYMBOLS; i++)
        if (lengths[i] > 0 && lengths[i] <= VVH_MAX_CODE_LEN)
            bl_count[lengths[i]]++;

    /* Compute first code for each length (MSB-first canonical) */
    uint16_t next_code[VVH_MAX_CODE_LEN + 1];
    uint16_t code = 0;
    next_code[0] = 0;
    for (int bits = 1; bits <= VVH_MAX_CODE_LEN; bits++) {
        code = (uint16_t)((code + bl_count[bits - 1]) << 1);
        next_code[bits] = code;
    }

    /* Assign codes in symbol order (canonical: sorted by length then symbol) */
    for (int i = 0; i < VVH_SYMBOLS; i++) {
        if (lengths[i] > 0)
            codes[i] = next_code[lengths[i]]++;
        else
            codes[i] = 0;
    }
}

/* ═══════════════════════════════════════════════════════════════
 * BUILD ENCODER TABLE
 * ═══════════════════════════════════════════════════════════════ */

static void build_enc_table(const uint32_t freq[VVH_SYMBOLS],
                             vvh_enc_table_t *enc) {
    build_code_lengths(freq, enc->lengths);

    uint16_t canonical[VVH_SYMBOLS];
    assign_canonical_codes(enc->lengths, canonical);

    /* Store bit-reversed codes for LSB-first writing */
    for (int i = 0; i < VVH_SYMBOLS; i++) {
        if (enc->lengths[i] > 0)
            enc->codes[i] = reverse_bits(canonical[i], enc->lengths[i]);
        else
            enc->codes[i] = 0;
    }
}

/* ═══════════════════════════════════════════════════════════════
 * BUILD DECODER TABLE
 * ═══════════════════════════════════════════════════════════════ */

static void build_dec_table(const uint8_t lengths[VVH_SYMBOLS],
                             vvh_dec_table_t *dec) {
    uint16_t canonical[VVH_SYMBOLS];
    assign_canonical_codes(lengths, canonical);

    memset(dec->table, 0, sizeof(dec->table));
    dec->slow_count = 0;

    for (int sym = 0; sym < VVH_SYMBOLS; sym++) {
        int len = lengths[sym];
        if (len == 0) continue;

        uint16_t rev = reverse_bits(canonical[sym], len);

        if (len <= VVH_DECODE_BITS) {
            /* Fast path: fill all entries where low `len` bits match `rev` */
            int fill = 1 << (VVH_DECODE_BITS - len);
            for (int j = 0; j < fill; j++) {
                int idx = (int)rev | (j << len);
                dec->table[idx] = (uint32_t)sym | ((uint32_t)len << 8);
            }
        } else {
            /* Slow path: store for linear scan */
            int si = dec->slow_count++;
            dec->slow_code[si] = rev;
            dec->slow_len[si] = (uint8_t)len;
            dec->slow_sym[si] = (uint8_t)sym;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════
 * WRITE HEADER (code lengths as packed nibbles)
 *
 * Format: [1B max_sym] [(max_sym+2)/2 bytes packed nibble pairs]
 * ═══════════════════════════════════════════════════════════════ */

static size_t write_header(const uint8_t lengths[VVH_SYMBOLS],
                            uint8_t *dst, size_t cap) {
    /* Find max symbol with nonzero length */
    int max_sym = 0;
    for (int i = VVH_SYMBOLS - 1; i >= 0; i--) {
        if (lengths[i] > 0) { max_sym = i; break; }
    }

    size_t hdr_size = 1 + ((size_t)max_sym + 2) / 2;
    if (hdr_size > cap) return 0;

    dst[0] = (uint8_t)max_sym;

    /* Pack nibble pairs */
    for (int i = 0; i <= max_sym; i += 2) {
        uint8_t hi = lengths[i];
        uint8_t lo = (i + 1 <= max_sym) ? lengths[i + 1] : 0;
        dst[1 + i / 2] = (uint8_t)((hi << 4) | (lo & 0x0F));
    }

    return hdr_size;
}

/* ═══════════════════════════════════════════════════════════════
 * READ HEADER
 * ═══════════════════════════════════════════════════════════════ */

static size_t read_header(const uint8_t *src, size_t src_len,
                           uint8_t lengths[VVH_SYMBOLS]) {
    memset(lengths, 0, VVH_SYMBOLS);
    if (src_len < 1) return 0;

    int max_sym = src[0];
    size_t hdr_size = 1 + ((size_t)max_sym + 2) / 2;
    if (hdr_size > src_len) return 0;

    for (int i = 0; i <= max_sym; i += 2) {
        uint8_t packed = src[1 + i / 2];
        lengths[i] = packed >> 4;
        if (i + 1 <= max_sym)
            lengths[i + 1] = packed & 0x0F;
    }

    return hdr_size;
}

/* ═══════════════════════════════════════════════════════════════
 * ENCODE
 * ═══════════════════════════════════════════════════════════════ */

vvh_error_t vvh_encode(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap, size_t *dst_len) {
    if (src_len == 0) {
        *dst_len = 0;
        return VVH_OK;
    }

    /* Count frequencies */
    uint32_t freq[VVH_SYMBOLS];
    memset(freq, 0, sizeof(freq));
    for (size_t i = 0; i < src_len; i++)
        freq[src[i]]++;

    /* Build encode table */
    vvh_enc_table_t enc;
    build_enc_table(freq, &enc);

    /* Check: any symbols with length 0 that appear in input? (shouldn't happen) */
    /* Write header */
    size_t hdr_sz = write_header(enc.lengths, dst, dst_cap);
    if (hdr_sz == 0) return VVH_ERR_OVERFLOW;

    /* Encode bitstream */
    bw_t w;
    bw_init(&w, dst + hdr_sz, dst_cap - hdr_sz);

    for (size_t i = 0; i < src_len; i++) {
        uint8_t sym = src[i];
        bw_add(&w, enc.codes[sym], enc.lengths[sym]);
    }

    size_t bs_sz = bw_flush(&w);
    size_t total = hdr_sz + bs_sz;

    /* Incompressible guard: if not smaller, signal failure */
    if (total >= src_len) {
        return VVH_ERR_OVERFLOW;
    }

    *dst_len = total;
    return VVH_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * DECODE
 *
 * PERFORMANCE-CRITICAL: the inner loop decodes one symbol per
 * iteration using a 12-bit table lookup + refill.
 *
 * Hot path (codes ≤ 12 bits, ~99% of symbols):
 *   1. Peek 12 bits from accumulator
 *   2. Table lookup → (symbol, length)
 *   3. Consume `length` bits
 *   4. Refill accumulator if needed
 *   5. Write symbol to output
 *
 * Cold path (codes 13-15 bits, <1% of symbols):
 *   Linear scan of slow_code/slow_len/slow_sym arrays.
 * ═══════════════════════════════════════════════════════════════ */

vvh_error_t vvh_decode(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap,
                       size_t num_literals, size_t *src_consumed) {
    if (num_literals == 0) {
        *src_consumed = 0;
        return VVH_OK;
    }
    if (num_literals > dst_cap) return VVH_ERR_OVERFLOW;

    /* Read header */
    uint8_t lengths[VVH_SYMBOLS];
    size_t hdr_sz = read_header(src, src_len, lengths);
    if (hdr_sz == 0) return VVH_ERR_CORRUPT;

    /* Check for valid tree: at least one nonzero length */
    int has_sym = 0;
    for (int i = 0; i < VVH_SYMBOLS; i++)
        if (lengths[i] > 0) { has_sym = 1; break; }
    if (!has_sym) return VVH_ERR_CORRUPT;

    /* Build decode table (heap-allocated: 16 KB) */
    vvh_dec_table_t *dec = (vvh_dec_table_t *)malloc(sizeof(vvh_dec_table_t));
    if (!dec) return VVH_ERR_NOMEM;
    build_dec_table(lengths, dec);

    /* Initialize bitstream reader */
    br_t r;
    br_init(&r, src + hdr_sz, src_len - hdr_sz);
    br_refill(&r);

    /* ─── Decode loop ─── */
    for (size_t i = 0; i < num_literals; i++) {
        /* Refill if accumulator is getting low */
        if (r.nbits < VVH_MAX_CODE_LEN)
            br_refill(&r);

        uint32_t peek = br_peek(&r, VVH_DECODE_BITS);
        uint32_t entry = dec->table[peek];
        int sym = (int)(entry & 0xFF);
        int len = (int)((entry >> 8) & 0xF);

        if (__builtin_expect(len > 0, 1)) {
            /* Fast path: code ≤ 12 bits */
            br_consume(&r, len);
            dst[i] = (uint8_t)sym;
        } else {
            /* Slow path: code > 12 bits */
            int found = 0;
            for (int s = 0; s < dec->slow_count; s++) {
                int slen = dec->slow_len[s];
                uint32_t mask = (1u << slen) - 1;
                if ((br_peek(&r, slen) & mask) == dec->slow_code[s]) {
                    br_consume(&r, slen);
                    dst[i] = dec->slow_sym[s];
                    found = 1;
                    break;
                }
            }
            if (!found) {
                free(dec);
                return VVH_ERR_CORRUPT;
            }
        }
    }

    /* Calculate bytes consumed from src */
    *src_consumed = hdr_sz + r.pos;
    /* Account for bits still in accumulator that we didn't fully consume */
    if (r.nbits >= 8) {
        /* We over-read by (nbits/8) bytes */
        size_t over = (size_t)(r.nbits / 8);
        if (*src_consumed >= over)
            *src_consumed -= over;
    }

    free(dec);
    return VVH_OK;
}
