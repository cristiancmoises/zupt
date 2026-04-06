/* VaptVupt codec — originally Apache-2.0 by Cristian Cezar Moisés
 * Integrated into Zupt — MIT License
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT AND Apache-2.0
 */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif

/*
 * VaptVupt — Decoder v2 (Sprint 1)
 *
 * KEY CHANGES:
 *   1. AVX2 inline copies in hot loop (eliminates function-pointer dispatch)
 *   2. Early offset load → prefetch match source before literal copy
 *   3. Safe-zone: skip per-byte bounds checks while far from buffer ends
 *   4. Pattern-fill SIMD for overlapping match (offset < 16)
 *   5. General path as fallback for tail bytes + non-AVX2 platforms
 */

#include "vaptvupt.h"
#include "vv_huffman.h"
#include "vv_ans.h"
#include <string.h>
#include <stdlib.h>

#if defined(__x86_64__) && defined(__AVX2__)
#include <immintrin.h>
#define VV_INLINE_AVX2 1
#else
#define VV_INLINE_AVX2 0
#endif

/* ─── Cold varint reader (out-of-line to keep hot loop compact) ─── */
__attribute__((noinline))
static size_t read_ext_len(const uint8_t **pp, const uint8_t *end) {
    size_t val = 0;
    const uint8_t *p = *pp;
    while (p < end) {
        uint8_t b = *p++;
        val += b;
        if (b < 255) break;
    }
    *pp = p;
    return val;
}

/* ═══════════════════════════════════════════════════════════════
 * INLINE SIMD HELPERS (AVX2 only, compiled on x86-64 -mavx2)
 * ═══════════════════════════════════════════════════════════════ */

#if VV_INLINE_AVX2

static inline void wcopy16(uint8_t *d, const uint8_t *s) {
    _mm_storeu_si128((__m128i *)d, _mm_loadu_si128((const __m128i *)s));
}
static inline void wcopy32(uint8_t *d, const uint8_t *s) {
    _mm256_storeu_si256((__m256i *)d, _mm256_loadu_si256((const __m256i *)s));
}

static inline void wcopy_n(uint8_t *d, const uint8_t *s, size_t n) {
    while (n >= 32) { wcopy32(d, s); d += 32; s += 32; n -= 32; }
    if (n >= 16) { wcopy16(d, s); d += 16; s += 16; n -= 16; }
    if (n > 0) wcopy16(d, s); /* safe over-copy in safe zone */
}

/* Match copy with offset >= 32: 32-byte chunks, NO over-copy at tail */
static inline void match_copy_32(uint8_t *d, const uint8_t *s, size_t n) {
    while (n >= 32) { wcopy32(d, s); d += 32; s += 32; n -= 32; }
    /* Exact tail: use 16-byte then memcpy to avoid corrupting future output */
    if (n >= 16) { wcopy16(d, s); d += 16; s += 16; n -= 16; }
    if (n > 0) __builtin_memcpy(d, s, n);
}

/* Match copy with offset 16-31: 16-byte chunks, exact tail */
static inline void match_copy_16(uint8_t *d, const uint8_t *s, size_t n) {
    while (n >= 16) { wcopy16(d, s); d += 16; s += 16; n -= 16; }
    if (n > 0) __builtin_memcpy(d, s, n);
}

/* Match copy with offset 8-15: 8-byte register copy */
static inline void match_copy_8(uint8_t *d, uint32_t off, size_t n) {
    const uint8_t *s = d - off;
    while (n >= 8) {
        uint64_t v; __builtin_memcpy(&v, s, 8);
        __builtin_memcpy(d, &v, 8);
        s += 8; d += 8; n -= 8;
    }
    while (n > 0) { *d++ = *s++; n--; }
}

/* Match copy with offset 1-7: byte-by-byte (correct for all offsets)
 * The 16-byte pattern-fill approach FAILS for offsets that don't divide 16
 * (e.g., offset=3: after 16 bytes the pattern misaligns). Since offset<16
 * is only ~5% of matches, byte-by-byte is fast enough. */
static inline void match_overlap(uint8_t *d, uint32_t off, size_t n) {
    const uint8_t *s = d - off;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

#endif /* VV_INLINE_AVX2 */

/* ═══════════════════════════════════════════════════════════════
 * DECODE BLOCK — TWO-TIER HOT PATH
 * ═══════════════════════════════════════════════════════════════ */

static vv_error_t decode_block_tokens(
    const uint8_t *ip, size_t ip_len,
    uint8_t *op, size_t dst_cap, size_t *out_len, int off_bytes,
    const uint8_t *dst_base)  /* Base of full output buffer for cross-block offset validation */
{
    const uint8_t *const ip_end = ip + ip_len;
    uint8_t *const op_start = op;
    uint8_t *const op_end = op + dst_cap;

    /* Safe zone boundaries: skip per-op bounds checks while inside.
     * Guard against underflow: if block is smaller than margin, skip fast path. */
    const uint8_t *const ip_safe = (ip_len > 24) ? (ip_end - 24) : ip;
    uint8_t *const op_safe = (dst_cap > 40) ? (op_end - 40) : op;

#if VV_INLINE_AVX2
    /* ═══ AVX2 FAST PATH ═══
     *
     * Runs while both ip and op are in the safe zone.
     * No per-byte bounds checks. Inline SIMD copies.
     * Prefetch match source at offset-load time.
     *
     * Per-sequence cost (common case, litlen≤14, matchlen≤18):
     *   token load + decode:   3 cycles
     *   early offset load:     4 cycles (overlapped)
     *   prefetch:              0 cycles (non-blocking)
     *   literal wcopy16:       5 cycles
     *   match wcopy32:         5 cycles
     *   pointer advance:       2 cycles
     *   loop branch:           0 cycles (predicted)
     *   ─────────────────────────────────
     *   Total: ~10 cycles for ~12 output bytes → 1.2 bytes/cycle
     *   At 4 GHz: ~4.8 GB/s (theoretical, real ~2-3 GB/s with cache)
     */
    while (__builtin_expect(ip < ip_safe && op < op_safe, 1)) {

        uint32_t token = *ip++;
        uint32_t ll = token >> 4;
        uint32_t mc = token & 0x0F;

        /* Extended literal length → cold path */
        if (__builtin_expect(ll == 15, 0))
            ll += (uint32_t)read_ext_len(&ip, ip_end);

        /* ── Early offset load + prefetch ──
         * The offset is at ip+ll (after the literal bytes).
         * Only do this for small litlen where we know ip+ll+2 is in the safe zone.
         * The safe-zone margin (24) guarantees: token(1) + lits(≤14) + offset(2) +
         * match_ext(≤6) + margin ≤ 24. */
        if (__builtin_expect(ll <= 14 && ip + ll + 2 <= ip_end, 1)) {
            uint16_t off_raw;
            __builtin_memcpy(&off_raw, ip + ll, 2);
            if (off_raw != 0 && off_raw <= (uint32_t)(op + ll - op_start))
                __builtin_prefetch(op + ll - off_raw, 0, 1);
        }

        /* ── Literal copy (EXACT — no wild over-copy) ──
         * Wild-copy writes garbage past op+ll that corrupts positions
         * referenced by future matches. Must use exact-length copies.
         * memcpy compiles to optimal SIMD for small constant-like sizes. */
        if (ll > 0)
            __builtin_memcpy(op, ip, ll);
        ip += ll;
        op += ll;

        /* ── End of block ── */
        if (__builtin_expect(ip >= ip_end, 0)) break;

        /* ── Offset ── */
        uint32_t offset = (off_bytes == 3) ? ((uint32_t)ip[0] | ((uint32_t)ip[1]<<8) | ((uint32_t)ip[2]<<16)) : vv_read16(ip);
        ip += off_bytes;

        /* ── Match length ── */
        uint32_t mlen = mc + VV_MIN_MATCH;
        if (__builtin_expect(mc == 15, 0))
            mlen += (uint32_t)read_ext_len(&ip, ip_end);

        /* ── Validate offset ── */
        if (__builtin_expect(offset == 0 || offset > (uint32_t)(op - dst_base), 0))
            return VV_ERR_CORRUPT;

        /* ── Match copy (inline AVX2, tiered by offset) ── */
        if (__builtin_expect(offset >= 32, 1)) {
            match_copy_32(op, op - offset, mlen);
        } else if (offset >= 16) {
            match_copy_16(op, op - offset, mlen);
        } else if (offset >= 8) {
            match_copy_8(op, offset, mlen);
        } else {
            match_overlap(op, offset, mlen);
        }
        op += mlen;
    }
#endif /* VV_INLINE_AVX2 */

    /* ═══ GENERAL PATH (tail + non-AVX2) ═══ */
    while (ip < ip_end) {
        uint8_t token = *ip++;
        size_t ll = token >> 4;
        size_t mc = token & 0x0F;

        if (__builtin_expect(ll == 15, 0))
            ll += read_ext_len(&ip, ip_end);

        if (__builtin_expect(ip + ll > ip_end, 0)) return VV_ERR_CORRUPT;
        if (__builtin_expect(op + ll > op_end, 0)) return VV_ERR_OVERFLOW;

        if (ll > 0) vv_copy_fast(op, ip, ll);
        ip += ll;
        op += ll;

        if (ip >= ip_end) break;

        if (__builtin_expect(ip + off_bytes > ip_end, 0)) return VV_ERR_CORRUPT;
        uint32_t offset = (off_bytes == 3) ? ((uint32_t)ip[0] | ((uint32_t)ip[1]<<8) | ((uint32_t)ip[2]<<16)) : vv_read16(ip);
        ip += off_bytes;

        size_t mlen = mc + VV_MIN_MATCH;
        if (__builtin_expect(mc == 15, 0))
            mlen += read_ext_len(&ip, ip_end);

        if (__builtin_expect(offset == 0 || offset > (uint32_t)(op - dst_base), 0))
            return VV_ERR_CORRUPT;
        if (__builtin_expect(op + mlen > op_end, 0))
            return VV_ERR_OVERFLOW;

        vv_copy_match(op, offset, mlen);
        op += mlen;
    }

    *out_len = (size_t)(op - op_start);
    return VV_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * DECODE STRIPPED TOKEN STREAM (for type 3 / Huffman blocks)
 *
 * Same as decode_block_tokens but literal bytes are NOT inline.
 * Instead, they come from a pre-decoded literal buffer.
 * Token format: same headers/offsets/extensions, just no literal bytes.
 * ═══════════════════════════════════════════════════════════════ */

static vv_error_t decode_stripped_tokens(
    const uint8_t *ip, size_t ip_len,       /* Stripped token stream */
    const uint8_t *lit_buf, size_t lit_len,  /* Pre-decoded literals */
    uint8_t *op, size_t dst_cap, size_t *out_len, int off_bytes,
    const uint8_t *dst_base)
{
    const uint8_t *ip_end = ip + ip_len;
    uint8_t *op_start = op;
    uint8_t *op_end = op + dst_cap;
    size_t lit_pos = 0;

    while (ip < ip_end) {
        uint8_t token = *ip++;
        size_t ll = token >> 4;
        size_t mc = token & 0x0F;

        /* Extended literal length */
        if (__builtin_expect(ll == 15, 0))
            ll += read_ext_len(&ip, ip_end);

        /* Copy literals from pre-decoded buffer */
        if (__builtin_expect(lit_pos + ll > lit_len, 0)) return VV_ERR_CORRUPT;
        if (__builtin_expect(op + ll > op_end, 0)) return VV_ERR_OVERFLOW;
        if (ll > 0) {
            memcpy(op, lit_buf + lit_pos, ll);
            lit_pos += ll;
        }
        op += ll;

        /* End of block: last sequence has no match */
        if (ip >= ip_end) break;

        /* Offset */
        if (__builtin_expect(ip + off_bytes > ip_end, 0)) return VV_ERR_CORRUPT;
        uint32_t offset = (off_bytes == 3) ? ((uint32_t)ip[0] | ((uint32_t)ip[1]<<8) | ((uint32_t)ip[2]<<16)) : vv_read16(ip);
        ip += off_bytes;

        /* Match length */
        size_t mlen = mc + VV_MIN_MATCH;
        if (__builtin_expect(mc == 15, 0))
            mlen += read_ext_len(&ip, ip_end);

        /* Validate */
        if (__builtin_expect(offset == 0 || offset > (uint32_t)(op - dst_base), 0)) {
            return VV_ERR_CORRUPT;
        }
        if (__builtin_expect(op + mlen > op_end, 0))
            return VV_ERR_OVERFLOW;

        /* Match copy */
        vv_copy_match(op, offset, mlen);
        op += mlen;
    }

    *out_len = (size_t)(op - op_start);
    return VV_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * DECODE TYPE 3 BLOCK (Huffman-compressed literals)
 *
 * Layout: [2B lit_count] [2B huff_section_size] [huff_data] [stripped_tokens]
 * ═══════════════════════════════════════════════════════════════ */

static vv_error_t decode_block_huffman(
    const uint8_t *data, size_t data_len,
    uint8_t *output, size_t decomp_size, size_t *out_len, int off_bytes,
    const uint8_t *dst_base)
{
    if (data_len < 4) return VV_ERR_CORRUPT;

    /* Read lit_count and huff_section_size */
    uint16_t lit_count = (uint16_t)(data[0] | (data[1] << 8));
    uint16_t huff_sz   = (uint16_t)(data[2] | (data[3] << 8));

    if (4 + (size_t)huff_sz > data_len) return VV_ERR_CORRUPT;

    /* Huffman-decode all literals */
    uint8_t *lit_buf = (uint8_t *)malloc((size_t)lit_count + 16);
    if (!lit_buf) return VV_ERR_NOMEM;

    size_t huff_consumed = 0;
    vvh_error_t herr = vvh_decode(data + 4, huff_sz, lit_buf, lit_count,
                                   lit_count, &huff_consumed);
    if (herr != VVH_OK) { free(lit_buf); return VV_ERR_CORRUPT; }

    /* Parse stripped token stream */
    const uint8_t *tokens = data + 4 + huff_sz;
    size_t tok_len = data_len - 4 - huff_sz;

    vv_error_t err = decode_stripped_tokens(tokens, tok_len,
                                             lit_buf, lit_count,
                                             output, decomp_size, out_len, off_bytes, dst_base);
    free(lit_buf);
    return err;
}

/* ═══════════════════════════════════════════════════════════════
 * DECODE TYPE 3 BLOCK (ANS-compressed literals, v0.5+)
 *
 * Layout: [2B lit_count] [2B ans_section_size] [ans_data] [stripped_tokens]
 * ═══════════════════════════════════════════════════════════════ */

static vv_error_t decode_block_ans(
    const uint8_t *data, size_t data_len,
    uint8_t *output, size_t decomp_size, size_t *out_len, int off_bytes,
    const uint8_t *dst_base)
{
    if (data_len < 4) return VV_ERR_CORRUPT;

    uint16_t lit_count = (uint16_t)(data[0] | (data[1] << 8));
    uint16_t ans_sz    = (uint16_t)(data[2] | (data[3] << 8));

    if (4 + (size_t)ans_sz > data_len) return VV_ERR_CORRUPT;

    /* ANS-decode all literals */
    uint8_t *lit_buf = (uint8_t *)malloc((size_t)lit_count + 16);
    if (!lit_buf) return VV_ERR_NOMEM;

    size_t ans_consumed = 0;
    vva_error_t aerr = vva_decode(data + 4, ans_sz, lit_buf, lit_count,
                                   lit_count, &ans_consumed);
    if (aerr != VVA_OK) { free(lit_buf); return VV_ERR_CORRUPT; }

    /* Parse stripped token stream */
    const uint8_t *tokens = data + 4 + ans_sz;
    size_t tok_len = data_len - 4 - ans_sz;

    vv_error_t err = decode_stripped_tokens(tokens, tok_len,
                                             lit_buf, lit_count,
                                             output, decomp_size, out_len, off_bytes, dst_base);
    free(lit_buf);
    return err;
}

/* ═══════════════════════════════════════════════════════════════
 * DECODE TYPE 3 BLOCK, TAG 'I' (4-way interleaved ANS, v0.6+)
 * ═══════════════════════════════════════════════════════════════ */

static vv_error_t decode_block_ans4(
    const uint8_t *data, size_t data_len,
    uint8_t *output, size_t decomp_size, size_t *out_len, int off_bytes,
    const uint8_t *dst_base)
{
    if (data_len < 4) return VV_ERR_CORRUPT;

    uint16_t lit_count = (uint16_t)(data[0] | (data[1] << 8));
    uint16_t ans_sz    = (uint16_t)(data[2] | (data[3] << 8));

    if (4 + (size_t)ans_sz > data_len) return VV_ERR_CORRUPT;

    uint8_t *lit_buf = (uint8_t *)malloc((size_t)lit_count + 16);
    if (!lit_buf) return VV_ERR_NOMEM;

    size_t ans_consumed = 0;
    vva_error_t aerr = vva_decode4(data + 4, ans_sz, lit_buf, lit_count,
                                    lit_count, &ans_consumed);
    if (aerr != VVA_OK) { free(lit_buf); return VV_ERR_CORRUPT; }

    const uint8_t *tokens = data + 4 + ans_sz;
    size_t tok_len = data_len - 4 - ans_sz;

    vv_error_t err = decode_stripped_tokens(tokens, tok_len,
                                             lit_buf, lit_count,
                                             output, decomp_size, out_len, off_bytes, dst_base);
    free(lit_buf);
    return err;
}

/* ═══════════════════════════════════════════════════════════════
 * DECODE TYPE 3 BLOCK, TAG 'C' (order-1 context model ANS, v0.7+)
 * ═══════════════════════════════════════════════════════════════ */

static vv_error_t decode_block_ctx(
    const uint8_t *data, size_t data_len,
    uint8_t *output, size_t decomp_size, size_t *out_len, int off_bytes,
    const uint8_t *dst_base)
{
    if (data_len < 4) return VV_ERR_CORRUPT;

    uint16_t lit_count = (uint16_t)(data[0] | (data[1] << 8));
    uint16_t ans_sz    = (uint16_t)(data[2] | (data[3] << 8));

    if (4 + (size_t)ans_sz > data_len) return VV_ERR_CORRUPT;

    uint8_t *lit_buf = (uint8_t *)malloc((size_t)lit_count + 16);
    if (!lit_buf) return VV_ERR_NOMEM;

    size_t ans_consumed = 0;
    vva_error_t aerr = vva_decode_ctx(data + 4, ans_sz, lit_buf, lit_count,
                                       lit_count, &ans_consumed);
    if (aerr != VVA_OK) { free(lit_buf); return VV_ERR_CORRUPT; }

    const uint8_t *tokens = data + 4 + ans_sz;
    size_t tok_len = data_len - 4 - ans_sz;

    vv_error_t err = decode_stripped_tokens(tokens, tok_len,
                                             lit_buf, lit_count,
                                             output, decomp_size, out_len, off_bytes, dst_base);
    free(lit_buf);
    return err;
}

/* ═══════════════════════════════════════════════════════════════
 * PUBLIC API: DECOMPRESS
 * ═══════════════════════════════════════════════════════════════ */

int64_t vv_decompress(const uint8_t *src, size_t src_len,
                      uint8_t *dst, size_t dst_cap) {
    if (!src || !dst) return VV_ERR_PARAM;
    if (src_len < sizeof(vv_frame_header_t)) return VV_ERR_CORRUPT;

    const uint8_t *ip = src;
    const uint8_t *ip_end = src + src_len;

    vv_frame_header_t fh;
    memcpy(&fh, ip, sizeof(fh));
    ip += sizeof(fh);

    if (fh.magic != VV_MAGIC) return VV_ERR_BAD_MAGIC;
    if (fh.version != 1) return VV_ERR_CORRUPT;

    int has_checksum = (fh.flags & 1);
    int off_bytes = (fh.window_log > 16) ? 3 : 2;
    uint8_t *op = dst;

    for (;;) {
        if (ip + 4 > ip_end) return VV_ERR_CORRUPT;
        uint32_t bh_packed;
        memcpy(&bh_packed, ip, 4); ip += 4;

        vv_block_type_t btype = vv_bh_type(bh_packed);
        int is_last = vv_bh_last(bh_packed);
        uint32_t dsz = vv_bh_size(bh_packed);

        if (dsz > VV_MAX_BLOCK_SIZE) return VV_ERR_OVERFLOW;
        if ((size_t)(op - dst) + dsz > dst_cap) return VV_ERR_OVERFLOW;

        if (btype == VV_BLOCK_RAW) {
            if (ip + dsz > ip_end) return VV_ERR_CORRUPT;
            memcpy(op, ip, dsz); ip += dsz; op += dsz;
        } else if (btype == VV_BLOCK_RLE) {
            if (ip >= ip_end) return VV_ERR_CORRUPT;
            memset(op, *ip++, dsz); op += dsz;
        } else if (btype == VV_BLOCK_COMPRESSED) {
            if (ip + 3 > ip_end) return VV_ERR_CORRUPT;
            uint32_t csz = (uint32_t)ip[0] | ((uint32_t)ip[1] << 8) | ((uint32_t)ip[2] << 16);
            ip += 3;
            if (ip + csz > ip_end) return VV_ERR_CORRUPT;

            size_t actual = 0;
            vv_error_t err = decode_block_tokens(ip, csz, op, dsz, &actual, off_bytes, dst);
            if (err != VV_OK) return err;
            if (actual != dsz) return VV_ERR_CORRUPT;
            ip += csz; op += dsz;
        } else if (btype == VV_BLOCK_ENTROPY) {
            /* Type 3: Entropy-coded literals + stripped LZ tokens
             * First byte after comp_size is the entropy tag:
             *   VV_ENTROPY_ANS ('A') or VV_ENTROPY_HUFFMAN ('H') */
            if (ip + 3 > ip_end) return VV_ERR_CORRUPT;
            uint32_t csz = (uint32_t)ip[0] | ((uint32_t)ip[1] << 8) | ((uint32_t)ip[2] << 16);
            ip += 3;
            if (csz < 1 || ip + csz > ip_end) return VV_ERR_CORRUPT;

            uint8_t tag = ip[0];
            const uint8_t *bdata = ip + 1;
            size_t bdata_len = csz - 1;
            size_t actual = 0;
            vv_error_t err;

            if (tag == VV_ENTROPY_ANS) {
                err = decode_block_ans(bdata, bdata_len, op, dsz, &actual, off_bytes, dst);
            } else if (tag == VV_ENTROPY_ANS4) {
                err = decode_block_ans4(bdata, bdata_len, op, dsz, &actual, off_bytes, dst);
            } else if (tag == VV_ENTROPY_CTX) {
                err = decode_block_ctx(bdata, bdata_len, op, dsz, &actual, off_bytes, dst);
            } else if (tag == VV_ENTROPY_SEQ) {
                /* Sequence coding: ANS on literals + ML + OF */
                err = vva_decode_sequences(bdata, bdata_len, op, dsz, &actual, dst);
                if (err != VV_OK) err = VV_ERR_CORRUPT;
            } else if (tag == VV_ENTROPY_HUFFMAN) {
                err = decode_block_huffman(bdata, bdata_len, op, dsz, &actual, off_bytes, dst);
            } else {
                return VV_ERR_CORRUPT;
            }
            if (err != VV_OK) return err;
            if (actual != dsz) return VV_ERR_CORRUPT;
            ip += csz; op += dsz;
        } else {
            return VV_ERR_CORRUPT;
        }
        if (is_last) break;
    }

    if (has_checksum) {
        if (ip + sizeof(vv_frame_footer_t) > ip_end) return VV_ERR_CORRUPT;
        vv_frame_footer_t ff;
        memcpy(&ff, ip, sizeof(ff));
        if (ff.footer_magic != 0x56564E44u) return VV_ERR_CORRUPT;
        uint64_t computed = vv_xxh64(dst, (size_t)(op - dst), 0);
        if (computed != ff.checksum) return VV_ERR_CORRUPT;
    }

    return (int64_t)(op - dst);
}
