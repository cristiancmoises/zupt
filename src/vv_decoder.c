/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Cristian Cezar Moisés
 * Commercial licensing: sac@securityops.co
 *
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
#include "vv_platform.h"
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
    if (n > 0) memcpy(d, s, n);
}

/* Match copy with offset 16-31: 16-byte chunks, exact tail */
static inline void match_copy_16(uint8_t *d, const uint8_t *s, size_t n) {
    while (n >= 16) { wcopy16(d, s); d += 16; s += 16; n -= 16; }
    if (n > 0) memcpy(d, s, n);
}

/* Match copy with offset 8-15: 8-byte register copy */
static inline void match_copy_8(uint8_t *d, uint32_t off, size_t n) {
    const uint8_t *s = d - off;
    while (n >= 8) {
        uint64_t v; memcpy(&v, s, 8);
        memcpy(d, &v, 8);
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

/* PERF: Force-inline core decode body so off_bytes becomes a compile-time
 * constant in each specialized variant, eliminating the ternary from the
 * hot path and enabling better branch prediction + offset loads. */
static __attribute__((always_inline)) inline vv_error_t
decode_block_tokens_impl(
    const uint8_t *ip, size_t ip_len,
    uint8_t *op, size_t dst_cap, size_t *out_len,
    const uint8_t *dst_base,
    const int off_bytes)  /* compile-time constant after inlining */
{
    const uint8_t *const ip_end = ip + ip_len;
    uint8_t *const op_start = op;
    uint8_t *const op_end = op + dst_cap;

    /* PERF: widened safe-zone margins (was 24/40).
     * Larger margins = fewer bound-check-triggered loop exits per block.
     * Exit boundary: max is 1 token + 14 lits + 3 offset + 6 match_ext = 24.
     * Plus match_copy_32 may over-copy 32 bytes past the real end, so
     * op needs at least 64 bytes of margin. */
    const uint8_t *const ip_safe = (ip_len > 48) ? (ip_end - 48) : ip;
    uint8_t *const op_safe = (dst_cap > 72) ? (op_end - 72) : op;

    /* PERF: once we've written enough bytes, any offset ≤ max_dist passes
     * the "offset > op - dst_base" check. Max offset is (1 << wlog) - 1,
     * at most (1<<20) - 1 for wlog=20. So past this threshold, only
     * offset==0 needs checking (invalid/corrupted). */
    const uint32_t max_valid_off = (off_bytes == 2) ? 0xFFFF : 0xFFFFFF;

#if VV_INLINE_AVX2
    /* PERF: two-phase fast path.
     * Phase 1 (warmup): op hasn't advanced far enough to make any offset
     *   automatically valid. Do full offset validation per sequence.
     * Phase 2 (hot): op - dst_base > max_valid_off, so any non-zero
     *   offset within 2/3 bytes is automatically valid — skip the
     *   (op - dst_base) comparison, keep only offset==0 check. */

    /* Phase 1: warmup — full validation */
    while (VV_LIKELY(ip < ip_safe && op < op_safe
                      && (uint32_t)(op - dst_base) <= max_valid_off)) {
        uint32_t token = *ip++;
        uint32_t ll = token >> 4;
        uint32_t mc = token & 0x0F;

        if (VV_UNLIKELY(ll == 15))
            ll += (uint32_t)read_ext_len(&ip, ip_end);

        if (VV_LIKELY(ll <= 14 && ip + ll + 2 <= ip_end)) {
            uint16_t off_raw;
            memcpy(&off_raw, ip + ll, 2);
            if (off_raw > 0)
                VV_PREFETCH(op + ll - off_raw);
        }

        if (ll > 0)
            memcpy(op, ip, ll);
        ip += ll;
        op += ll;

        if (VV_UNLIKELY(ip >= ip_end)) break;

        uint32_t offset;
        if (off_bytes == 2) {
            offset = vv_read16(ip);
        } else {
            offset = (uint32_t)ip[0] | ((uint32_t)ip[1]<<8) | ((uint32_t)ip[2]<<16);
        }
        ip += off_bytes;

        uint32_t mlen = mc + VV_MIN_MATCH;
        if (VV_UNLIKELY(mc == 15))
            mlen += (uint32_t)read_ext_len(&ip, ip_end);

        if (VV_UNLIKELY(offset == 0 || offset > (uint32_t)(op - dst_base)))
            return VV_ERR_CORRUPT;

        if (VV_LIKELY(offset >= 32)) {
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

    /* Phase 2: hot path — op is far enough in that any non-zero offset
     * within 2-byte or 3-byte range is automatically valid. */
    while (VV_LIKELY(ip < ip_safe && op < op_safe)) {
        uint32_t token = *ip++;
        uint32_t ll = token >> 4;
        uint32_t mc = token & 0x0F;

        if (VV_UNLIKELY(ll == 15))
            ll += (uint32_t)read_ext_len(&ip, ip_end);

        if (VV_LIKELY(ll <= 14 && ip + ll + 2 <= ip_end)) {
            uint16_t off_raw;
            memcpy(&off_raw, ip + ll, 2);
            if (off_raw > 0)
                VV_PREFETCH(op + ll - off_raw);
        }

        if (ll > 0)
            memcpy(op, ip, ll);
        ip += ll;
        op += ll;

        if (VV_UNLIKELY(ip >= ip_end)) break;

        uint32_t offset;
        if (off_bytes == 2) {
            offset = vv_read16(ip);
        } else {
            offset = (uint32_t)ip[0] | ((uint32_t)ip[1]<<8) | ((uint32_t)ip[2]<<16);
        }
        ip += off_bytes;

        uint32_t mlen = mc + VV_MIN_MATCH;
        if (VV_UNLIKELY(mc == 15))
            mlen += (uint32_t)read_ext_len(&ip, ip_end);

        /* No (op - dst_base) check needed — op is past max_valid_off */
        if (VV_UNLIKELY(offset == 0))
            return VV_ERR_CORRUPT;

        if (VV_LIKELY(offset >= 32)) {
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
#endif

    /* General path (tail + non-AVX2) */
    while (ip < ip_end) {
        uint8_t token = *ip++;
        size_t ll = token >> 4;
        size_t mc = token & 0x0F;

        if (VV_UNLIKELY(ll == 15))
            ll += read_ext_len(&ip, ip_end);

        if (VV_UNLIKELY(ip + ll > ip_end)) return VV_ERR_CORRUPT;
        if (VV_UNLIKELY(op + ll > op_end)) return VV_ERR_OVERFLOW;

        if (ll > 0) vv_copy_fast(op, ip, ll);
        ip += ll;
        op += ll;

        if (ip >= ip_end) break;

        if (VV_UNLIKELY(ip + off_bytes > ip_end)) return VV_ERR_CORRUPT;
        uint32_t offset;
        if (off_bytes == 2) {
            offset = vv_read16(ip);
        } else {
            offset = (uint32_t)ip[0] | ((uint32_t)ip[1]<<8) | ((uint32_t)ip[2]<<16);
        }
        ip += off_bytes;

        size_t mlen = mc + VV_MIN_MATCH;
        if (VV_UNLIKELY(mc == 15))
            mlen += read_ext_len(&ip, ip_end);

        if (VV_UNLIKELY(offset == 0 || offset > (uint32_t)(op - dst_base)))
            return VV_ERR_CORRUPT;
        if (VV_UNLIKELY(op + mlen > op_end))
            return VV_ERR_OVERFLOW;

        vv_copy_match(op, offset, mlen);
        op += mlen;
    }

    *out_len = (size_t)(op - op_start);
    return VV_OK;
}

/* Specialized for 2-byte offsets (wlog ≤ 16) — the common fast path */
static vv_error_t decode_block_tokens_w16(
    const uint8_t *ip, size_t ip_len,
    uint8_t *op, size_t dst_cap, size_t *out_len,
    const uint8_t *dst_base)
{
    return decode_block_tokens_impl(ip, ip_len, op, dst_cap, out_len, dst_base, 2);
}

/* Specialized for 3-byte offsets (wlog > 16) */
static vv_error_t decode_block_tokens_w20(
    const uint8_t *ip, size_t ip_len,
    uint8_t *op, size_t dst_cap, size_t *out_len,
    const uint8_t *dst_base)
{
    return decode_block_tokens_impl(ip, ip_len, op, dst_cap, out_len, dst_base, 3);
}

static vv_error_t decode_block_tokens(
    const uint8_t *ip, size_t ip_len,
    uint8_t *op, size_t dst_cap, size_t *out_len, int off_bytes,
    const uint8_t *dst_base)
{
    if (off_bytes == 2)
        return decode_block_tokens_w16(ip, ip_len, op, dst_cap, out_len, dst_base);
    return decode_block_tokens_w20(ip, ip_len, op, dst_cap, out_len, dst_base);
}

/* ═══════════════════════════════════════════════════════════════
 * DECODE STRIPPED TOKEN STREAM (for type 3 / Huffman blocks)
 *
 * Same as decode_block_tokens but literal bytes are NOT inline.
 * Instead, they come from a pre-decoded literal buffer.
 * Token format: same headers/offsets/extensions, just no literal bytes.
 * ═══════════════════════════════════════════════════════════════ */

/* PERF: force-inline body so off_bytes becomes a compile-time constant */
static __attribute__((always_inline)) inline vv_error_t
decode_stripped_tokens_impl(
    const uint8_t *ip, size_t ip_len,
    const uint8_t *lit_buf, size_t lit_len,
    uint8_t *op, size_t dst_cap, size_t *out_len,
    const uint8_t *dst_base,
    const int off_bytes)
{
    const uint8_t *ip_end = ip + ip_len;
    uint8_t *op_start = op;
    uint8_t *op_end = op + dst_cap;
    size_t lit_pos = 0;

    while (ip < ip_end) {
        uint8_t token = *ip++;
        size_t ll = token >> 4;
        size_t mc = token & 0x0F;

        if (VV_UNLIKELY(ll == 15))
            ll += read_ext_len(&ip, ip_end);

        if (VV_UNLIKELY(lit_pos + ll > lit_len)) return VV_ERR_CORRUPT;
        if (VV_UNLIKELY(op + ll > op_end)) return VV_ERR_OVERFLOW;
        if (ll > 0) {
            memcpy(op, lit_buf + lit_pos, ll);
            lit_pos += ll;
        }
        op += ll;

        if (ip >= ip_end) break;

        if (VV_UNLIKELY(ip + off_bytes > ip_end)) return VV_ERR_CORRUPT;
        /* PERF: off_bytes is compile-time constant here */
        uint32_t offset;
        if (off_bytes == 2) {
            offset = vv_read16(ip);
        } else {
            offset = (uint32_t)ip[0] | ((uint32_t)ip[1]<<8) | ((uint32_t)ip[2]<<16);
        }
        ip += off_bytes;

        size_t mlen = mc + VV_MIN_MATCH;
        if (VV_UNLIKELY(mc == 15))
            mlen += read_ext_len(&ip, ip_end);

        if (VV_UNLIKELY(offset == 0 || offset > (uint32_t)(op - dst_base))) {
            return VV_ERR_CORRUPT;
        }
        if (VV_UNLIKELY(op + mlen > op_end))
            return VV_ERR_OVERFLOW;

        vv_copy_match(op, offset, mlen);
        op += mlen;
    }

    *out_len = (size_t)(op - op_start);
    return VV_OK;
}

static vv_error_t decode_stripped_tokens(
    const uint8_t *ip, size_t ip_len,
    const uint8_t *lit_buf, size_t lit_len,
    uint8_t *op, size_t dst_cap, size_t *out_len, int off_bytes,
    const uint8_t *dst_base)
{
    if (off_bytes == 2) {
        return decode_stripped_tokens_impl(ip, ip_len, lit_buf, lit_len,
                                            op, dst_cap, out_len, dst_base, 2);
    }
    return decode_stripped_tokens_impl(ip, ip_len, lit_buf, lit_len,
                                        op, dst_cap, out_len, dst_base, 3);
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
    return vv_decompress_flags(src, src_len, dst, dst_cap, VV_DECOMPRESS_DEFAULT);
}

int64_t vv_decompress_flags(const uint8_t *src, size_t src_len,
                            uint8_t *dst, size_t dst_cap,
                            uint32_t flags) {
    if (!src || !dst) return VV_ERR_PARAM;
    if (src_len < sizeof(vv_frame_header_t)) return VV_ERR_CORRUPT;

    const uint8_t *ip = src;
    const uint8_t *ip_end = src + src_len;
    uint8_t *op = dst;
    uint8_t *op_end = dst + dst_cap;

    /* MULTI-FRAME: a .vv file may contain one or more concatenated frames
     * (useful for parallel encode, Zupt-style archives, append-mode
     * writes). We decode frames in a loop until input is exhausted. */
    while (ip < ip_end) {
        if (ip + sizeof(vv_frame_header_t) > ip_end) return VV_ERR_CORRUPT;

        vv_frame_header_t fh;
        memcpy(&fh, ip, sizeof(fh));
        ip += sizeof(fh);

        if (fh.magic != VV_MAGIC) return VV_ERR_BAD_MAGIC;
        if (fh.version != 1) return VV_ERR_CORRUPT;

        int has_checksum = (fh.flags & 1);
        int off_bytes = (fh.window_log > 16) ? 3 : 2;

        /* Per-frame dst_base: matches must resolve only within this frame.
         * Multi-frame files mean frame 2's matches don't reach into
         * frame 1's output — each frame is independently decodable. */
        uint8_t *frame_out_start = op;

        for (;;) {
            if (ip + 4 > ip_end) return VV_ERR_CORRUPT;
            uint32_t bh_packed;
            memcpy(&bh_packed, ip, 4); ip += 4;

            vv_block_type_t btype = vv_bh_type(bh_packed);
            int is_last = vv_bh_last(bh_packed);
            uint32_t dsz = vv_bh_size(bh_packed);

            if (dsz > VV_MAX_BLOCK_SIZE) return VV_ERR_OVERFLOW;
            if ((size_t)(op - dst) + dsz > dst_cap) return VV_ERR_OVERFLOW;
            (void)op_end;

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
                vv_error_t err = decode_block_tokens(ip, csz, op, dsz, &actual, off_bytes, frame_out_start);
                if (err != VV_OK) return err;
                if (actual != dsz) return VV_ERR_CORRUPT;
                ip += csz; op += dsz;
            } else if (btype == VV_BLOCK_ENTROPY) {
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
                    err = decode_block_ans(bdata, bdata_len, op, dsz, &actual, off_bytes, frame_out_start);
                } else if (tag == VV_ENTROPY_ANS4) {
                    err = decode_block_ans4(bdata, bdata_len, op, dsz, &actual, off_bytes, frame_out_start);
                } else if (tag == VV_ENTROPY_CTX) {
                    err = decode_block_ctx(bdata, bdata_len, op, dsz, &actual, off_bytes, frame_out_start);
                } else if (tag == VV_ENTROPY_SEQ) {
                    err = vva_decode_sequences(bdata, bdata_len, op, dsz, &actual, frame_out_start);
                    if (err != VV_OK) err = VV_ERR_CORRUPT;
                } else if (tag == VV_ENTROPY_SEQ_V2) {
                    /* 'T' tag: sequence coding with min_match=3. Wire
                     * payload identical to 'S', only ml_base differs. */
                    err = vva_decode_sequences_v2(bdata, bdata_len, op, dsz, &actual, frame_out_start);
                    if (err != VV_OK) err = VV_ERR_CORRUPT;
                } else if (tag == VV_ENTROPY_HUFFMAN) {
                    err = decode_block_huffman(bdata, bdata_len, op, dsz, &actual, off_bytes, frame_out_start);
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
            /* PERF: caller may skip XXH64 when another layer (e.g. AES-GCM)
             * already verifies integrity. Still validate footer magic above
             * to catch truncation. */
            if (!(flags & VV_DECOMPRESS_SKIP_CHECKSUM)) {
                uint64_t computed = vv_xxh64(frame_out_start, (size_t)(op - frame_out_start), 0);
                if (computed != ff.checksum) return VV_ERR_CORRUPT;
            }
            ip += sizeof(vv_frame_footer_t);
        }

        /* Loop back to try another frame (if input remains) */
    }

    return (int64_t)(op - dst);
}

/* ═══════════════════════════════════════════════════════════════
 * STREAMING DECOMPRESSION
 *
 * Incoming compressed bytes arrive in arbitrary chunks. Structure:
 *   1. Frame header (16 bytes) — must be accumulated before any
 *      blocks can be decoded
 *   2. Zero or more blocks, each: [4B header][3B csz][payload]
 *   3. Optional frame footer (16 bytes) — checksum validation
 *
 * Strategy: buffer incoming bytes in an internal growing buffer,
 * parse as much as we can at each call, and emit decoded output.
 *
 * For correct match decoding across blocks, we emit directly into
 * the caller's dst buffer and preserve dst_base so that sequences
 * referencing earlier decoded bytes resolve correctly. The caller
 * is responsible for providing a large enough dst buffer: the same
 * constraint as one-shot decompression.
 * ═══════════════════════════════════════════════════════════════ */

typedef enum {
    VV_DSTREAM_HEADER,
    VV_DSTREAM_BLOCK,
    VV_DSTREAM_FOOTER,
    VV_DSTREAM_DONE,
    VV_DSTREAM_ERROR
} vv_dstream_state_t;

struct vv_dstream_s {
    vv_dstream_state_t state;
    vv_frame_header_t  fh;
    int                has_checksum;
    int                off_bytes;

    /* Input-side buffer for incomplete blocks/headers */
    uint8_t *in_buf;
    size_t   in_cap;
    size_t   in_len;

    /* Output position tracking (for checksum and bookkeeping) */
    size_t   output_pos;
    uint8_t *dst_base_saved; /* Preserved across calls; matches caller dst */

    /* Streaming checksum of decoded output */
    vv_xxh64_state_t cks;
};

vv_dstream_t *vv_dstream_create(void) {
    vv_dstream_t *ctx = (vv_dstream_t *)calloc(1, sizeof(vv_dstream_t));
    if (!ctx) return NULL;
    ctx->state = VV_DSTREAM_HEADER;
    ctx->in_cap = 65536;
    ctx->in_buf = (uint8_t *)malloc(ctx->in_cap);
    if (!ctx->in_buf) { free(ctx); return NULL; }
    vv_xxh64_init(&ctx->cks, 0);
    return ctx;
}

void vv_dstream_destroy(vv_dstream_t *ctx) {
    if (!ctx) return;
    free(ctx->in_buf);
    free(ctx);
}

int vv_dstream_reset(vv_dstream_t *ctx) {
    if (!ctx) return VV_ERR_PARAM;
    /* Keep in_buf and in_cap (reuse scratch); clear everything else */
    ctx->state = VV_DSTREAM_HEADER;
    ctx->has_checksum = 0;
    ctx->off_bytes = 0;
    ctx->in_len = 0;
    ctx->output_pos = 0;
    ctx->dst_base_saved = NULL;
    memset(&ctx->fh, 0, sizeof(ctx->fh));
    vv_xxh64_init(&ctx->cks, 0);
    return VV_OK;
}

/* Grow in_buf to at least need bytes */
static int dstream_reserve(vv_dstream_t *ctx, size_t need) {
    if (need <= ctx->in_cap) return 0;
    size_t new_cap = ctx->in_cap;
    while (new_cap < need) new_cap *= 2;
    uint8_t *new_buf = (uint8_t *)realloc(ctx->in_buf, new_cap);
    if (!new_buf) return -1;
    ctx->in_buf = new_buf;
    ctx->in_cap = new_cap;
    return 0;
}

/* Append bytes to input buffer */
static int dstream_append(vv_dstream_t *ctx, const uint8_t *src, size_t src_len) {
    if (dstream_reserve(ctx, ctx->in_len + src_len) != 0) return -1;
    memcpy(ctx->in_buf + ctx->in_len, src, src_len);
    ctx->in_len += src_len;
    return 0;
}

/* Consume first n bytes from input buffer */
static void dstream_consume(vv_dstream_t *ctx, size_t n) {
    if (n >= ctx->in_len) ctx->in_len = 0;
    else {
        memmove(ctx->in_buf, ctx->in_buf + n, ctx->in_len - n);
        ctx->in_len -= n;
    }
}

int vv_dstream_decompress_chunk(vv_dstream_t *ctx,
                                const uint8_t *src, size_t src_len,
                                uint8_t *dst, size_t dst_cap,
                                size_t *consumed, size_t *written) {
    if (!ctx || !dst || !consumed || !written) return VV_ERR_PARAM;
    *consumed = 0;
    *written = 0;

    if (ctx->state == VV_DSTREAM_ERROR) return VV_ERR_CORRUPT;
    if (ctx->state == VV_DSTREAM_DONE) return 1;

    /* Append new input */
    if (src_len > 0) {
        if (dstream_append(ctx, src, src_len) != 0) {
            ctx->state = VV_DSTREAM_ERROR;
            return VV_ERR_NOMEM;
        }
        *consumed = src_len;
    }

    /* Remember dst_base for match resolution across blocks */
    if (!ctx->dst_base_saved) ctx->dst_base_saved = dst;
    /* Output position within dst (must match caller's expected write offset) */
    uint8_t *op = dst + ctx->output_pos;

    /* State machine: process as much as we can */
    for (;;) {
        if (ctx->state == VV_DSTREAM_HEADER) {
            if (ctx->in_len < sizeof(vv_frame_header_t)) { *written = ctx->output_pos; return VV_OK; }
            memcpy(&ctx->fh, ctx->in_buf, sizeof(vv_frame_header_t));
            if (ctx->fh.magic != VV_MAGIC) { ctx->state = VV_DSTREAM_ERROR; return VV_ERR_BAD_MAGIC; }
            if (ctx->fh.version != 1) { ctx->state = VV_DSTREAM_ERROR; return VV_ERR_CORRUPT; }
            ctx->has_checksum = (ctx->fh.flags & 1);
            ctx->off_bytes = (ctx->fh.window_log > 16) ? 3 : 2;
            dstream_consume(ctx, sizeof(vv_frame_header_t));
            ctx->state = VV_DSTREAM_BLOCK;
        }

        if (ctx->state == VV_DSTREAM_BLOCK) {
            /* Need at least 4 bytes for block header */
            if (ctx->in_len < 4) { *written = ctx->output_pos; return VV_OK; }

            uint32_t bh_packed;
            memcpy(&bh_packed, ctx->in_buf, 4);
            vv_block_type_t btype = vv_bh_type(bh_packed);
            int is_last = vv_bh_last(bh_packed);
            uint32_t dsz = vv_bh_size(bh_packed);

            if (dsz > VV_MAX_BLOCK_SIZE) { ctx->state = VV_DSTREAM_ERROR; return VV_ERR_OVERFLOW; }
            if ((size_t)(op - dst) + dsz > dst_cap) { ctx->state = VV_DSTREAM_ERROR; return VV_ERR_OVERFLOW; }

            /* Determine how many bytes this block occupies */
            size_t block_header_sz = 4;
            size_t block_data_sz = 0;

            if (btype == VV_BLOCK_RAW) {
                block_data_sz = dsz;
            } else if (btype == VV_BLOCK_RLE) {
                block_data_sz = 1;
            } else if (btype == VV_BLOCK_COMPRESSED || btype == VV_BLOCK_ENTROPY) {
                if (ctx->in_len < block_header_sz + 3) { *written = ctx->output_pos; return VV_OK; }
                const uint8_t *p = ctx->in_buf + block_header_sz;
                uint32_t csz = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
                block_data_sz = 3 + csz;
            } else {
                ctx->state = VV_DSTREAM_ERROR; return VV_ERR_CORRUPT;
            }

            size_t total_block_sz = block_header_sz + block_data_sz;
            if (ctx->in_len < total_block_sz) { *written = ctx->output_pos; return VV_OK; }

            /* Decode the block — decoder uses dst_base for match resolution */
            const uint8_t *p = ctx->in_buf + block_header_sz;
            if (btype == VV_BLOCK_RAW) {
                memcpy(op, p, dsz);
            } else if (btype == VV_BLOCK_RLE) {
                memset(op, p[0], dsz);
            } else if (btype == VV_BLOCK_COMPRESSED) {
                uint32_t csz = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
                size_t actual = 0;
                vv_error_t err = decode_block_tokens(p + 3, csz, op, dsz, &actual,
                                                      ctx->off_bytes, ctx->dst_base_saved);
                if (err != VV_OK || actual != dsz) { ctx->state = VV_DSTREAM_ERROR; return err != VV_OK ? err : VV_ERR_CORRUPT; }
            } else { /* ENTROPY */
                uint32_t csz = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
                uint8_t tag = p[3];
                const uint8_t *bdata = p + 4;
                size_t bdata_len = csz - 1;
                size_t actual = 0;
                vv_error_t err;
                if (tag == VV_ENTROPY_ANS) {
                    err = decode_block_ans(bdata, bdata_len, op, dsz, &actual, ctx->off_bytes, ctx->dst_base_saved);
                } else if (tag == VV_ENTROPY_ANS4) {
                    err = decode_block_ans4(bdata, bdata_len, op, dsz, &actual, ctx->off_bytes, ctx->dst_base_saved);
                } else if (tag == VV_ENTROPY_CTX) {
                    err = decode_block_ctx(bdata, bdata_len, op, dsz, &actual, ctx->off_bytes, ctx->dst_base_saved);
                } else if (tag == VV_ENTROPY_SEQ) {
                    err = vva_decode_sequences(bdata, bdata_len, op, dsz, &actual, ctx->dst_base_saved);
                    if (err != VV_OK) err = VV_ERR_CORRUPT;
                } else if (tag == VV_ENTROPY_SEQ_V2) {
                    err = vva_decode_sequences_v2(bdata, bdata_len, op, dsz, &actual, ctx->dst_base_saved);
                    if (err != VV_OK) err = VV_ERR_CORRUPT;
                } else if (tag == VV_ENTROPY_HUFFMAN) {
                    err = decode_block_huffman(bdata, bdata_len, op, dsz, &actual, ctx->off_bytes, ctx->dst_base_saved);
                } else {
                    ctx->state = VV_DSTREAM_ERROR; return VV_ERR_CORRUPT;
                }
                if (err != VV_OK || actual != dsz) { ctx->state = VV_DSTREAM_ERROR; return err != VV_OK ? err : VV_ERR_CORRUPT; }
            }

            /* Update checksum (over decoded output) */
            if (ctx->has_checksum && dsz > 0) {
                vv_xxh64_update(&ctx->cks, op, dsz);
            }

            op += dsz;
            ctx->output_pos += dsz;
            dstream_consume(ctx, total_block_sz);

            if (is_last) {
                ctx->state = ctx->has_checksum ? VV_DSTREAM_FOOTER : VV_DSTREAM_DONE;
            }
        }

        if (ctx->state == VV_DSTREAM_FOOTER) {
            if (ctx->in_len < sizeof(vv_frame_footer_t)) { *written = ctx->output_pos; return VV_OK; }
            vv_frame_footer_t ff;
            memcpy(&ff, ctx->in_buf, sizeof(ff));
            if (ff.footer_magic != 0x56564E44u) { ctx->state = VV_DSTREAM_ERROR; return VV_ERR_CORRUPT; }
            uint64_t computed = vv_xxh64_finalize(&ctx->cks);
            if (computed != ff.checksum) { ctx->state = VV_DSTREAM_ERROR; return VV_ERR_CORRUPT; }
            dstream_consume(ctx, sizeof(vv_frame_footer_t));
            ctx->state = VV_DSTREAM_DONE;
        }

        if (ctx->state == VV_DSTREAM_DONE) {
            *written = ctx->output_pos;
            return 1;
        }
    }
}
