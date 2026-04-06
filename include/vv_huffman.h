/* VaptVupt codec — originally Apache-2.0 by Cristian Cezar Moisés
 * Integrated into Zupt — MIT License
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT AND Apache-2.0
 */

/*
 * VaptVupt — Canonical Huffman Codec
 *
 * Standalone header: can be used independently with VV_HUFFMAN_STANDALONE.
 * Designed for embedding in Zupt or any other LZ codec.
 *
 * API:
 *   vvh_encode() — compress raw literals into Huffman bitstream
 *   vvh_decode() — decompress Huffman bitstream back to raw literals
 *
 * Format:
 *   [1B max_symbol] [packed nibble code lengths] [LSB-first bitstream]
 *
 * Performance targets:
 *   Encode: ≥ 150 MB/s   Decode: ≥ 800 MB/s   (x86-64, -O2)
 */
#ifndef VV_HUFFMAN_H
#define VV_HUFFMAN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════
 * CONSTANTS
 * ═══════════════════════════════════════════════════════════════ */

#define VVH_SYMBOLS        256
#define VVH_MAX_CODE_LEN   15
#define VVH_DECODE_BITS    12
#define VVH_DECODE_SIZE    (1 << VVH_DECODE_BITS)  /* 4096 entries */

/* ═══════════════════════════════════════════════════════════════
 * ERROR CODES (compatible with vv_error_t when not standalone)
 * ═══════════════════════════════════════════════════════════════ */

#ifdef VV_HUFFMAN_STANDALONE
typedef enum {
    VVH_OK          =  0,
    VVH_ERR_CORRUPT = -2,
    VVH_ERR_NOMEM   = -3,
    VVH_ERR_OVERFLOW= -4,
} vvh_error_t;
#else
#include "vaptvupt.h"
typedef vv_error_t vvh_error_t;
#define VVH_OK           VV_OK
#define VVH_ERR_CORRUPT  VV_ERR_CORRUPT
#define VVH_ERR_NOMEM    VV_ERR_NOMEM
#define VVH_ERR_OVERFLOW VV_ERR_OVERFLOW
#endif

/* ═══════════════════════════════════════════════════════════════
 * ENCODE TABLE (used by encoder only)
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  lengths[VVH_SYMBOLS];    /* Code length per symbol (0 = absent) */
    uint16_t codes[VVH_SYMBOLS];      /* Bit-reversed canonical codes (LSB-first) */
} vvh_enc_table_t;

/* ═══════════════════════════════════════════════════════════════
 * DECODE TABLE (used by decoder only)
 *
 * 12-bit lookup: 4096 entries × 4 bytes = 16 KB (L1-resident).
 * Entry: bits [7:0] = symbol, bits [11:8] = code length.
 * Symbols with code length > 12 use a slow path.
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t table[VVH_DECODE_SIZE];  /* Fast lookup (codes ≤ 12 bits) */
    /* Slow table for codes 13-15 bits (max 256 entries) */
    uint16_t slow_code[VVH_SYMBOLS];  /* Bit-reversed code */
    uint8_t  slow_len[VVH_SYMBOLS];   /* Code length */
    uint8_t  slow_sym[VVH_SYMBOLS];   /* Symbol value */
    int      slow_count;              /* Number of slow-path symbols */
} vvh_dec_table_t;

/* ═══════════════════════════════════════════════════════════════
 * PUBLIC API
 * ═══════════════════════════════════════════════════════════════ */

/*
 * Encode raw literal bytes into Huffman bitstream.
 *
 * src[0..src_len-1]  — raw literal bytes
 * dst[0..dst_cap-1]  — output buffer (header + bitstream)
 * *dst_len           — on success, set to actual compressed size
 *
 * Returns VVH_OK on success, or VVH_ERR_OVERFLOW if dst too small.
 * If compressed size >= src_len, returns VVH_ERR_OVERFLOW (incompressible).
 */
vvh_error_t vvh_encode(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap, size_t *dst_len);

/*
 * Decode Huffman bitstream back to raw literal bytes.
 *
 * src[0..src_len-1]   — compressed data (header + bitstream)
 * dst[0..dst_cap-1]   — output buffer for decoded literals
 * num_literals        — expected number of decoded symbols
 * *src_consumed       — on success, bytes consumed from src
 *
 * Returns VVH_OK on success, or error code.
 */
vvh_error_t vvh_decode(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap,
                       size_t num_literals, size_t *src_consumed);

/*
 * Upper bound on compressed size for src_len literal bytes.
 */
static inline size_t vvh_bound(size_t src_len) {
    /* header (129 max) + bitstream (15 bits/symbol worst case) + slack */
    return 129 + (src_len * 15 + 7) / 8 + 8;
}

#ifdef __cplusplus
}
#endif
#endif /* VV_HUFFMAN_H */
