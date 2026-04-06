/* VaptVupt codec — originally Apache-2.0 by Cristian Cezar Moisés
 * Integrated into Zupt — MIT License
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT AND Apache-2.0
 */

/*
 * VaptVupt — tANS Entropy Codec (v2: sparse header + 4-way interleaved)
 *
 * Standalone: define VV_ANS_STANDALONE to use without VaptVupt.
 * ZUPT-COMPAT: this header has zero VaptVupt dependencies when standalone.
 *
 * v0.6 changes:
 *   - Adaptive sparse/dense header (Item 1): 3× smaller on typical data
 *   - 4-way interleaved encode/decode (Item 2): ~2.5× faster decode
 */
#ifndef VV_ANS_H
#define VV_ANS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VVA_TABLE_LOG    12
#define VVA_TABLE_SIZE   (1 << VVA_TABLE_LOG)   /* 4096 */
#define VVA_MAX_SYMBOL   256

/* Header format discriminators */
#define VVA_HDR_SINGLE   0x01  /* Single symbol: 0-bit encoding */
#define VVA_HDR_SPARSE   0x02  /* ≤32 active symbols: (sym,freq) pairs */
#define VVA_HDR_DENSE    0x03  /* >32 active symbols: max_sym + freq array */
/* ZUPT-COMPAT: v0.5 legacy format detected by first byte being 0x00-0xFF
 * without matching any HDR_* code — fall back to old read path. */
#define VVA_HDR_LEGACY   0x00  /* v0.5 format: [max_sym] [2B×(max_sym+1)] */

#ifdef VV_ANS_STANDALONE
typedef enum {
    VVA_OK            =  0,
    VVA_ERR_IO        = -1,
    VVA_ERR_CORRUPT   = -2,
    VVA_ERR_NOMEM     = -3,
    VVA_ERR_OVERFLOW  = -4,
    VVA_ERR_PARAM     = -6,
} vva_error_t;
#else
#include "vaptvupt.h"
typedef vv_error_t vva_error_t;
#define VVA_OK            VV_OK
#define VVA_ERR_CORRUPT   VV_ERR_CORRUPT
#define VVA_ERR_NOMEM     VV_ERR_NOMEM
#define VVA_ERR_OVERFLOW  VV_ERR_OVERFLOW
#define VVA_ERR_PARAM     VV_ERR_PARAM
#endif

typedef struct {
    uint8_t  symbol;
    uint8_t  nbits;
    uint16_t baseline;
} vva_dec_entry_t;

/* ═══ Public API ═══ */

/* Single-stream encode/decode (tag 'A', backward compat with v0.5) */
vva_error_t vva_encode(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap, size_t *dst_len);

vva_error_t vva_decode(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap,
                       size_t num_literals, size_t *src_consumed);

/* 4-way interleaved encode/decode (tag 'I', v0.6+) */
vva_error_t vva_encode4(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap, size_t *dst_len);

vva_error_t vva_decode4(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap,
                        size_t num_literals, size_t *src_consumed);

/* Order-1 context model encode/decode (tag 'C', v0.7+)
 * Uses 256 ANS tables — one per previous byte. Contexts with too few
 * observations inherit from the global table. 4 MB decode memory. */
vva_error_t vva_encode_ctx(const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_cap, size_t *dst_len);

vva_error_t vva_decode_ctx(const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_cap,
                           size_t num_literals, size_t *src_consumed);

/* ═══ Sequence coding (tag 'S', v0.8+) ═══
 * ZUPT-COMPAT: available when VV_ANS_STANDALONE is defined.
 *
 * Encodes an LZ token stream using 3 ANS tables: literals, match-length
 * codes (36 symbols), and offset codes (24 symbols). Replaces raw varint
 * storage of match metadata, saving 8-15% on typical data.
 *
 * Input token format (from LZ engine):
 *   [token: litlen:4|matchlen:4] [litlen_ext] [literal_bytes] [2B offset LE] [matchlen_ext]
 * Output: [3 table headers] [4B seq_count] [4B lit_count] [ANS bitstream]
 */

#define VVA_ML_CODES  36   /* Match length code count */
#define VVA_OF_CODES  27   /* Offset code count: 3 rep + 24 explicit */

vva_error_t vva_encode_sequences(const uint8_t *tokens, size_t tok_len,
                                  uint8_t *dst, size_t dst_cap, size_t *dst_len,
                                  int off_bytes);

vva_error_t vva_decode_sequences(const uint8_t *src, size_t src_len,
                                  uint8_t *dst, size_t dst_cap, size_t *dst_len,
                                  const uint8_t *dst_base);

static inline size_t vva_bound(size_t src_len) {
    /* Context model header can be up to ~10KB, seq coding adds 3 table headers */
    return 12288 + (src_len * 15 + 7) / 8 + 16;
}

#ifdef __cplusplus
}
#endif
#endif /* VV_ANS_H */
