/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
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
    int      overflow;
} bw_t;

static inline void bw_init(bw_t *w, uint8_t *dst, size_t cap) {
    w->bits = 0; w->nbits = 0; w->dst = dst; w->pos = 0; w->cap = cap;
    w->overflow = 0;
}

/* Add up to 16 bits. Flushes full bytes automatically. */
static inline void bw_add(bw_t *w, uint32_t val, int n) {
    w->bits |= (uint64_t)(val & ((1u << n) - 1)) << w->nbits;
    w->nbits += n;
    /* Flush complete bytes */
    while (w->nbits >= 8) {
        if (w->pos == w->cap) {
            /* Keep the accumulator bounded after capacity exhaustion;
             * later symbols must never shift by 64 or more. Flush
             * reports the sticky error to the encoder. */
            w->overflow = 1;
            w->bits = 0;
            w->nbits = 0;
            return;
        }
        w->dst[w->pos++] = (uint8_t)(w->bits);
        w->bits >>= 8;
        w->nbits -= 8;
    }
}

static inline size_t bw_flush(bw_t *w) {
    if (w->overflow) return SIZE_MAX;
    while (w->nbits > 0 && w->pos < w->cap) {
        w->dst[w->pos++] = (uint8_t)(w->bits);
        w->bits >>= 8;
        w->nbits -= 8;
    }
    return w->nbits > 0 ? SIZE_MAX : w->pos;
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

/* Refill: load bytes until accumulator is full (≥56 bits).
 * SPRINT 124: bulk 8-byte fast path. The byte-at-a-time loop was up
 * to 7 dependent load-shift-or iterations firing every 3-4 symbols
 * per stream — measured as the top cost of Huffman literal decode.
 * One unaligned 8-byte load + mask absorbs the same bytes; the tail
 * (<8 bytes left) keeps the exact byte loop. */
static inline void br_refill(br_t *r) {
    if (r->pos + 8 <= r->len) {
        unsigned absorbed = (63u - (unsigned)r->nbits) >> 3;   /* 0..7 */
        uint64_t chunk;
        memcpy(&chunk, r->src + r->pos, 8);
        chunk &= ((uint64_t)1 << (absorbed * 8)) - 1;
        r->bits |= chunk << r->nbits;
        r->pos += absorbed;
        r->nbits += (int)(absorbed * 8);
        return;
    }
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
    if (bs_sz == SIZE_MAX) return VVH_ERR_OVERFLOW;
    size_t total = hdr_sz + bs_sz;

    /* Incompressible guard: if not smaller, signal failure */
    if (total >= src_len) {
        return VVH_ERR_OVERFLOW;
    }

    *dst_len = total;
    return VVH_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * 4-STREAM INTERLEAVED ENCODE (Sprint 103, Phase A)
 *
 * Splits input into 4 round-robin streams sharing a single Huffman
 * table. The decoder runs 4 independent decoders in parallel,
 * gaining instruction-level parallelism (1.8-2.2× decode throughput).
 *
 * Wire format (after the standard code-length header):
 *   [3B stream1_size] [3B stream2_size] [3B stream3_size]
 *   [stream0_bitstream] [stream1_bitstream] [stream2_bitstream] [stream3_bitstream]
 *
 * Stream0's size is implicit: total - 9 - hdr_sz - s1 - s2 - s3.
 * Each stream is byte-aligned at its start (clean entry for decoder).
 *
 * Activation guard: src_len >= 1024. Below this, single-stream wins
 * on overhead (9-byte stream-size header + per-stream alignment slop
 * dominates).
 *
 * See CHANGELOG.md (Sprint 105) for the design rationale.
 * ═══════════════════════════════════════════════════════════════ */

#define VVH4_STREAM_HDR_SZ 9   /* 3 bytes × 3 stream sizes */
#define VVH4_MIN_LITERALS  1024

vvh_error_t vvh_encode4(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, size_t *dst_len) {
    /* Activation guard: 4-stream is only profitable above 1024 lits. */
    if (src_len < VVH4_MIN_LITERALS) return VVH_ERR_OVERFLOW;

    /* Need at least: code-length header (~129B) + 9B stream-hdr +
     * 4 streams of nonzero size. Conservative lower bound. */
    if (dst_cap < 200) return VVH_ERR_OVERFLOW;

    /* ─── 1. Count frequencies (single shared table) ─── */
    uint32_t freq[VVH_SYMBOLS];
    memset(freq, 0, sizeof(freq));
    for (size_t i = 0; i < src_len; i++)
        freq[src[i]]++;

    /* ─── 2. Build encode table (shared across all 4 streams) ─── */
    vvh_enc_table_t enc;
    build_enc_table(freq, &enc);

    /* ─── 3. Write code-length header ─── */
    size_t hdr_sz = write_header(enc.lengths, dst, dst_cap);
    if (hdr_sz == 0) return VVH_ERR_OVERFLOW;

    /* ─── 4. Reserve 9 bytes for stream-size header (backpatched) ─── */
    if (hdr_sz + VVH4_STREAM_HDR_SZ >= dst_cap) return VVH_ERR_OVERFLOW;
    uint8_t *stream_hdr = dst + hdr_sz;
    size_t streams_offset = hdr_sz + VVH4_STREAM_HDR_SZ;

    /* ─── 5. Encode each stream into the dst buffer ─── */
    /* Per-stream symbol counts for round-robin distribution:
     *   stream0 gets indices 0, 4, 8, ..., (src_len + 3) / 4 symbols
     *   stream1 gets indices 1, 5, 9, ..., (src_len + 2) / 4 symbols
     *   stream2 gets indices 2, 6, 10, ..., (src_len + 1) / 4 symbols
     *   stream3 gets indices 3, 7, 11, ..., src_len / 4 symbols
     */
    size_t cur_off = streams_offset;
    size_t stream_sizes[4];

    for (int s = 0; s < 4; s++) {
        if (cur_off >= dst_cap) return VVH_ERR_OVERFLOW;
        bw_t w;
        bw_init(&w, dst + cur_off, dst_cap - cur_off);

        /* Round-robin: encode symbols at indices s, s+4, s+8, ... */
        for (size_t i = (size_t)s; i < src_len; i += 4) {
            uint8_t sym = src[i];
            /* enc.lengths[sym] could be 0 only if the symbol never
             * appeared in input — but we just counted and it did, so
             * length > 0 for every symbol we encode. Defensive check
             * for static analyzer happiness: */
            if (enc.lengths[sym] == 0) return VVH_ERR_CORRUPT;
            bw_add(&w, enc.codes[sym], enc.lengths[sym]);
        }

        size_t sz = bw_flush(&w);
        if (sz == SIZE_MAX) return VVH_ERR_OVERFLOW;
        stream_sizes[s] = sz;
        cur_off += sz;
    }

    /* ─── 6. Backpatch stream-size header (3 bytes per stream, LE) ─── */
    /* Stream 0 size is implicit; encode streams 1, 2, 3 here.
     * Each size is stored as 24-bit little-endian (max 16 MB / stream
     * — far above any realistic literal-block size). */
    for (int s = 1; s <= 3; s++) {
        size_t sz = stream_sizes[s];
        if (sz > 0xFFFFFF) return VVH_ERR_OVERFLOW;  /* >16MB stream */
        uint8_t *p = stream_hdr + (s - 1) * 3;
        p[0] = (uint8_t)(sz & 0xFF);
        p[1] = (uint8_t)((sz >> 8) & 0xFF);
        p[2] = (uint8_t)((sz >> 16) & 0xFF);
    }

    size_t total = cur_off;

    /* Incompressible guard: same convention as vvh_encode. */
    if (total >= src_len) return VVH_ERR_OVERFLOW;

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

static void release_decode_table(vvh_dec_table_t *dec, const void *workspace) {
    if (!workspace) free(dec);
}

static vvh_error_t vvh_decode_impl(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap,
                       size_t num_literals, size_t *src_consumed,
                       vvh_dec_table_t *workspace) {
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

    /* Caller-owned table storage avoids a per-block allocation. */
    vvh_dec_table_t *dec = workspace ? workspace :
        (vvh_dec_table_t *)malloc(sizeof(vvh_dec_table_t));
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

        if (VV_LIKELY(len > 0)) {
            /* Fast path: code ≤ 12 bits */
            if (r.nbits < len) { release_decode_table(dec, workspace); return VVH_ERR_CORRUPT; }
            br_consume(&r, len);
            dst[i] = (uint8_t)sym;
        } else {
            /* Slow path: code > 12 bits */
            int found = 0;
            for (int s = 0; s < dec->slow_count; s++) {
                int slen = dec->slow_len[s];
                uint32_t mask = (1u << slen) - 1;
                if (r.nbits >= slen &&
                    (br_peek(&r, slen) & mask) == dec->slow_code[s]) {
                    br_consume(&r, slen);
                    dst[i] = dec->slow_sym[s];
                    found = 1;
                    break;
                }
            }
            if (!found) {
                release_decode_table(dec, workspace);
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

    release_decode_table(dec, workspace);
    return VVH_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * 4-STREAM INTERLEAVED DECODE (Sprint 104, Phase B)
 *
 * Production decoder for the wire format produced by vvh_encode4.
 * Runs 4 independent decoders in parallel using a single shared
 * decode table. Each iteration of the hot loop performs 4 lookups
 * with no inter-decoder data dependencies, allowing the OoO engine
 * to pipeline them.
 *
 * Wire format expected (see vvh_encode4):
 *   [code-length header] [3B s1] [3B s2] [3B s3]
 *   [stream0_data] [stream1_data] [stream2_data] [stream3_data]
 *
 * Stream0's size is implicit. All four streams share one Huffman
 * table built from the code-length header.
 * ═══════════════════════════════════════════════════════════════ */

static vvh_error_t vvh_decode4_impl(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap,
                        size_t num_literals, size_t *src_consumed,
                        vvh_dec_table_t *workspace) {
    if (num_literals == 0) {
        *src_consumed = 0;
        return VVH_OK;
    }
    if (num_literals > dst_cap) return VVH_ERR_OVERFLOW;

    /* ─── 1. Read code-length header ─── */
    uint8_t lengths[VVH_SYMBOLS];
    size_t hdr_sz = read_header(src, src_len, lengths);
    if (hdr_sz == 0) return VVH_ERR_CORRUPT;

    /* Validate at least one nonzero length */
    int has_sym = 0;
    for (int i = 0; i < VVH_SYMBOLS; i++)
        if (lengths[i] > 0) { has_sym = 1; break; }
    if (!has_sym) return VVH_ERR_CORRUPT;

    /* ─── 2. Read 9-byte stream-size header ─── */
    if (hdr_sz + VVH4_STREAM_HDR_SZ > src_len) return VVH_ERR_CORRUPT;
    const uint8_t *sh = src + hdr_sz;
    size_t s1 = (size_t)sh[0] | ((size_t)sh[1] << 8) | ((size_t)sh[2] << 16);
    size_t s2 = (size_t)sh[3] | ((size_t)sh[4] << 8) | ((size_t)sh[5] << 16);
    size_t s3 = (size_t)sh[6] | ((size_t)sh[7] << 8) | ((size_t)sh[8] << 16);

    /* ─── 3. Validate stream sizes (DoS-resistant bounds checks) ─── */
    size_t streams_off = hdr_sz + VVH4_STREAM_HDR_SZ;
    if (streams_off > src_len) return VVH_ERR_CORRUPT;
    size_t streams_total = src_len - streams_off;
    /* Overflow-safe check: s1 + s2 + s3 <= streams_total */
    if (s1 > streams_total) return VVH_ERR_CORRUPT;
    if (s2 > streams_total - s1) return VVH_ERR_CORRUPT;
    if (s3 > streams_total - s1 - s2) return VVH_ERR_CORRUPT;
    size_t s0 = streams_total - s1 - s2 - s3;
    /* All streams must be non-zero unless num_literals < 4 (degenerate) */
    if (num_literals >= 4) {
        if (s0 == 0 || s1 == 0 || s2 == 0 || s3 == 0) return VVH_ERR_CORRUPT;
    }

    /* ─── 4. Build decode table (shared across all 4 streams) ─── */
    vvh_dec_table_t *dec = workspace ? workspace :
        (vvh_dec_table_t *)malloc(sizeof(vvh_dec_table_t));
    if (!dec) return VVH_ERR_NOMEM;
    build_dec_table(lengths, dec);

    /* ─── 5. Initialize 4 independent bitstream readers ─── */
    br_t r0, r1, r2, r3;
    br_init(&r0, src + streams_off,                  s0);
    br_init(&r1, src + streams_off + s0,             s1);
    br_init(&r2, src + streams_off + s0 + s1,        s2);
    br_init(&r3, src + streams_off + s0 + s1 + s2,   s3);
    br_refill(&r0); br_refill(&r1); br_refill(&r2); br_refill(&r3);

    /* ─── 6. Per-stream symbol counts (round-robin) ─── */
    /* num_literals = 4*Q + R where R in {0,1,2,3}.
     *   stream 0 decodes Q + (R >= 1) symbols
     *   stream 1 decodes Q + (R >= 2) symbols
     *   stream 2 decodes Q + (R >= 3) symbols
     *   stream 3 decodes Q symbols */
    size_t Q = num_literals / 4;

    /* Helper: decode one symbol. Inlined manually below for ILP. */
    #define DEC_ONE(R, OUT) do { \
        if ((R).nbits < VVH_MAX_CODE_LEN) br_refill(&(R)); \
        uint32_t peek = br_peek(&(R), VVH_DECODE_BITS); \
        uint32_t entry = dec->table[peek]; \
        int sym = (int)(entry & 0xFF); \
        int len = (int)((entry >> 8) & 0xF); \
        if (VV_LIKELY(len > 0)) { \
            if ((R).nbits < len) { release_decode_table(dec, workspace); return VVH_ERR_CORRUPT; } \
            br_consume(&(R), len); \
            (OUT) = (uint8_t)sym; \
        } else { \
            int found = 0; \
            for (int s = 0; s < dec->slow_count; s++) { \
                int slen = dec->slow_len[s]; \
                uint32_t mask = (1u << slen) - 1; \
                if ((R).nbits >= slen && \
                    (br_peek(&(R), slen) & mask) == dec->slow_code[s]) { \
                    br_consume(&(R), slen); \
                    (OUT) = dec->slow_sym[s]; \
                    found = 1; \
                    break; \
                } \
            } \
            if (!found) { release_decode_table(dec, workspace); return VVH_ERR_CORRUPT; } \
        } \
    } while (0)

    /* Variant without the per-symbol refill check, for rounds where a
     * bulk refill has already guaranteed enough bits (see below). */
    #define DEC_ONE_NR(R, OUT) do { \
        uint32_t peek = br_peek(&(R), VVH_DECODE_BITS); \
        uint32_t entry = dec->table[peek]; \
        int sym = (int)(entry & 0xFF); \
        int len = (int)((entry >> 8) & 0xF); \
        if (VV_LIKELY(len > 0)) { \
            br_consume(&(R), len); \
            (OUT) = (uint8_t)sym; \
        } else { \
            int found = 0; \
            for (int s = 0; s < dec->slow_count; s++) { \
                int slen = dec->slow_len[s]; \
                uint32_t mask = (1u << slen) - 1; \
                if ((br_peek(&(R), slen) & mask) == dec->slow_code[s]) { \
                    br_consume(&(R), slen); \
                    (OUT) = dec->slow_sym[s]; \
                    found = 1; \
                    break; \
                } \
            } \
            if (!found) { release_decode_table(dec, workspace); return VVH_ERR_CORRUPT; } \
        } \
    } while (0)

    /* ─── 7. Hot loop: decode 4 symbols per iteration ─── */
    /* Each iteration's 4 decodes are fully independent — different
     * readers, different table peeks, different output positions.
     * Modern OoO engines can pipeline 4 independent decode chains
     * achieving ~1.8-2.2× speedup over single-stream.
     *
     * SPRINT 127: refill-hoisted fast rounds. One bulk refill per lane
     * guarantees >= 56 accumulator bits (its 8-byte fast path applies
     * whenever pos + 8 <= len, which the loop guard checks per lane),
     * and three symbols consume at most 3 x VVH_MAX_CODE_LEN = 45 bits
     * — so each round decodes 3 symbols per lane (12 outputs) with a
     * single refill branch per lane instead of one per symbol. Bit
     * consumption and decode order are identical to the per-symbol
     * loop; corrupt input still bottoms out at the same slow-path
     * check, and nbits cannot underflow (56 - 45 >= 0). The tail and
     * the last rounds fall back to the checked DEC_ONE loop. */
    size_t out_idx = 0;
    size_t i = 0;
    while (i + 3 <= Q &&
           r0.pos + 8 <= r0.len && r1.pos + 8 <= r1.len &&
           r2.pos + 8 <= r2.len && r3.pos + 8 <= r3.len) {
        br_refill(&r0); br_refill(&r1); br_refill(&r2); br_refill(&r3);
        for (int k = 0; k < 3; k++) {
            uint8_t y0, y1, y2, y3;
            DEC_ONE_NR(r0, y0);
            DEC_ONE_NR(r1, y1);
            DEC_ONE_NR(r2, y2);
            DEC_ONE_NR(r3, y3);
            dst[out_idx + 0] = y0;
            dst[out_idx + 1] = y1;
            dst[out_idx + 2] = y2;
            dst[out_idx + 3] = y3;
            out_idx += 4;
        }
        i += 3;
    }
    for (; i < Q; i++) {
        uint8_t y0, y1, y2, y3;
        DEC_ONE(r0, y0);
        DEC_ONE(r1, y1);
        DEC_ONE(r2, y2);
        DEC_ONE(r3, y3);
        dst[out_idx + 0] = y0;
        dst[out_idx + 1] = y1;
        dst[out_idx + 2] = y2;
        dst[out_idx + 3] = y3;
        out_idx += 4;
    }

    /* ─── 8. Tail (handle remaining 0-3 symbols) ─── */
    size_t tail = num_literals - Q * 4;
    if (tail >= 1) { uint8_t y; DEC_ONE(r0, y); dst[out_idx++] = y; }
    if (tail >= 2) { uint8_t y; DEC_ONE(r1, y); dst[out_idx++] = y; }
    if (tail >= 3) { uint8_t y; DEC_ONE(r2, y); dst[out_idx++] = y; }

    #undef DEC_ONE
    #undef DEC_ONE_NR

    /* Total bytes consumed: header + stream-size header + all 4 streams */
    *src_consumed = streams_off + s0 + s1 + s2 + s3;

    release_decode_table(dec, workspace);
    return VVH_OK;
}

size_t vvh_decode_workspace_size(void) {
    return sizeof(vvh_dec_table_t);
}

size_t vvh_decode_workspace_alignment(void) {
    return _Alignof(vvh_dec_table_t);
}

static vvh_error_t check_decode_workspace(void *workspace, size_t cap) {
    if (!workspace || (uintptr_t)workspace % _Alignof(vvh_dec_table_t))
        return VVH_ERR_PARAM;
    if (cap < sizeof(vvh_dec_table_t)) return VVH_ERR_OVERFLOW;
    return VVH_OK;
}

vvh_error_t vvh_decode(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap,
                       size_t num_literals, size_t *src_consumed) {
    return vvh_decode_impl(src, src_len, dst, dst_cap, num_literals,
                           src_consumed, NULL);
}

vvh_error_t vvh_decode4(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap,
                        size_t num_literals, size_t *src_consumed) {
    return vvh_decode4_impl(src, src_len, dst, dst_cap, num_literals,
                            src_consumed, NULL);
}

vvh_error_t vvh_decode_with_workspace(const uint8_t *src, size_t src_len,
                                      uint8_t *dst, size_t dst_cap,
                                      size_t num_literals, size_t *src_consumed,
                                      void *workspace, size_t workspace_cap) {
    if (!src_consumed || (!src && src_len) || (!dst && dst_cap)) return VVH_ERR_PARAM;
    if (!num_literals) { *src_consumed = 0; return VVH_OK; }
    if (!src || !dst) return VVH_ERR_PARAM;
    if (num_literals > dst_cap) return VVH_ERR_OVERFLOW;
    vvh_error_t err = check_decode_workspace(workspace, workspace_cap);
    if (err != VVH_OK) return err;
    return vvh_decode_impl(src, src_len, dst, dst_cap, num_literals,
                           src_consumed, (vvh_dec_table_t *)workspace);
}

vvh_error_t vvh_decode4_with_workspace(const uint8_t *src, size_t src_len,
                                       uint8_t *dst, size_t dst_cap,
                                       size_t num_literals, size_t *src_consumed,
                                       void *workspace, size_t workspace_cap) {
    if (!src_consumed || (!src && src_len) || (!dst && dst_cap)) return VVH_ERR_PARAM;
    if (!num_literals) { *src_consumed = 0; return VVH_OK; }
    if (!src || !dst) return VVH_ERR_PARAM;
    if (num_literals > dst_cap) return VVH_ERR_OVERFLOW;
    vvh_error_t err = check_decode_workspace(workspace, workspace_cap);
    if (err != VVH_OK) return err;
    return vvh_decode4_impl(src, src_len, dst, dst_cap, num_literals,
                            src_consumed, (vvh_dec_table_t *)workspace);
}
