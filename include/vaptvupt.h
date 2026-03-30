/* VaptVupt codec — originally Apache-2.0 by Cristian Cezar Moisés
 * Integrated into Zupt — MIT License
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT AND Apache-2.0
 */
/*
 * VaptVupt Codec — Next-generation lossless compression
 * Public API and data structures
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 Cristian.
 * Zero dependencies. Pure C11.
 */
#ifndef VAPTVUPT_H
#define VAPTVUPT_H

#include <stdint.h>
#include <stddef.h>

/* VAPTVUPT: When integrated into Zupt, pull in zupt_xxh64 declaration */
#ifndef VV_STANDALONE
#include "zupt.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════
 * VERSION & CONSTANTS
 * ═══════════════════════════════════════════════════════════════ */

#define VV_VERSION_MAJOR  0
#define VV_VERSION_MINOR  1
#define VV_VERSION_PATCH  0
#define VV_VERSION_STRING "0.1.0"

#define VV_MAGIC          0x56560100u  /* "VV\x01\x00" */
#define VV_MAX_BLOCK_SIZE (1u << 20)   /* 1 MB per block */
#define VV_MIN_MATCH      4
#define VV_MAX_MATCH      65535
#define VV_MAX_LIT_RUN    65535
#define VV_MAX_OFFSET     (1u << 24)   /* 16 MB default window */

/* ═══════════════════════════════════════════════════════════════
 * ERROR CODES
 * ═══════════════════════════════════════════════════════════════ */

typedef enum {
    VV_OK            =  0,
    VV_ERR_IO        = -1,
    VV_ERR_CORRUPT   = -2,
    VV_ERR_NOMEM     = -3,
    VV_ERR_OVERFLOW  = -4,
    VV_ERR_BAD_MAGIC = -5,
    VV_ERR_PARAM     = -6,
} vv_error_t;

/* ═══════════════════════════════════════════════════════════════
 * COMPRESSION MODES
 * ═══════════════════════════════════════════════════════════════ */

typedef enum {
    VV_MODE_ULTRA_FAST = 0,  /* Speed priority: greedy parse, no entropy */
    VV_MODE_BALANCED   = 1,  /* Default: lazy parse + Huffman */
    VV_MODE_EXTREME    = 2,  /* Ratio priority: optimal parse + Huffman */
} vv_mode_t;

/* ═══════════════════════════════════════════════════════════════
 * BLOCK TYPES (2-bit field in block header)
 * ═══════════════════════════════════════════════════════════════ */

typedef enum {
    VV_BLOCK_RAW        = 0,  /* Uncompressed (stored) */
    VV_BLOCK_COMPRESSED = 1,  /* LZ + raw literals */
    VV_BLOCK_RLE        = 2,  /* Run-length (single byte) */
    VV_BLOCK_ENTROPY    = 3,  /* LZ + entropy-coded literals (ANS or Huffman) */
} vv_block_type_t;

/* Entropy sub-type tags (first byte of entropy section in type-3 blocks) */
#define VV_ENTROPY_HUFFMAN  0x48  /* 'H' — Huffman (v0.3-v0.4) */
#define VV_ENTROPY_ANS      0x41  /* 'A' — tANS single-stream (v0.5) */
#define VV_ENTROPY_ANS4     0x49  /* 'I' — tANS 4-way interleaved (v0.6+) */
#define VV_ENTROPY_CTX      0x43  /* 'C' — tANS order-1 context model (v0.7+) */
#define VV_ENTROPY_SEQ      0x53  /* 'S' — sequence coding: ANS on lits+ml+of (v0.8+) */

/* Block header accessors (2-bit type, 1-bit last, 21-bit size) */
static inline vv_block_type_t vv_bh_type(uint32_t h)  { return (vv_block_type_t)(h & 3); }
static inline int      vv_bh_last(uint32_t h)  { return (h >> 2) & 1; }
static inline uint32_t vv_bh_size(uint32_t h)  { return (h >> 3) & 0x1FFFFF; }
static inline uint32_t vv_bh_pack(vv_block_type_t t, int last, uint32_t sz) {
    return (uint32_t)t | ((uint32_t)last << 2) | (sz << 3);
}

/* ═══════════════════════════════════════════════════════════════
 * TOKEN TYPES (in the sequence stream)
 *
 * Each token is: [type:2][litlen:6] [optional litlen ext]
 *                [literal bytes]
 *                [matchlen ext] [offset bytes]
 *
 * The decoder reads a compact token byte, copies literals,
 * then copies a match. This is LZ4-like for speed.
 * ═══════════════════════════════════════════════════════════════ */

/* Token byte layout:
 *   Bits 7-4: literal_length (0-14, 15=extended)
 *   Bits 3-0: match_length - VV_MIN_MATCH (0-14, 15=extended)
 *
 * Followed by:
 *   [extended literal length varint, if litlen==15]
 *   [literal bytes]
 *   [offset: 2 bytes LE (or 3 bytes if high bit set)]
 *   [extended match length varint, if matchlen==15]
 */

/* ═══════════════════════════════════════════════════════════════
 * ON-DISK STRUCTURES
 * ═══════════════════════════════════════════════════════════════ */

#pragma pack(push, 1)

/* Frame header: 16 bytes */
typedef struct {
    uint32_t magic;           /* VV_MAGIC */
    uint8_t  version;         /* Format version (1) */
    uint8_t  flags;           /* bit0: has_checksum, bit1: has_dict */
    uint8_t  mode_hint;       /* Compression mode used (informational) */
    uint8_t  window_log;      /* Window size = 1 << window_log */
    uint64_t content_size;    /* Uncompressed size (0 = unknown) */
} vv_frame_header_t;

/* Block header: 4 bytes */
typedef struct {
    /* Bits 0-1:   block_type (vv_block_type_t) */
    /* Bit  2:     last_block flag */
    /* Bits 3-23:  decompressed_size (max 1 MB) */
    /* Bits 24-31: reserved */
    uint32_t packed;
} vv_block_header_t;

/* Frame footer: 12 bytes */
typedef struct {
    uint64_t checksum;        /* XXH64 of decompressed content */
    uint32_t footer_magic;    /* 0x56564E44 = "VVND" */
} vv_frame_footer_t;

#pragma pack(pop)

/* Block header accessors defined above with block type enum */

/* ═══════════════════════════════════════════════════════════════
 * MATCHER STATE
 * ═══════════════════════════════════════════════════════════════ */

#define VV_HC_BITS    18
#define VV_HC_SIZE    (1u << VV_HC_BITS)

typedef struct {
    int32_t  table[VV_HC_SIZE];   /* Hash → most recent position */
    int32_t *chain;               /* Chain array (window_size entries) */
    uint32_t window_size;
    uint32_t chain_depth;         /* Max chain traversal (level-dependent) */
} vv_matcher_t;

/* ═══════════════════════════════════════════════════════════════
 * HUFFMAN TABLES (entropy coding)
 *
 * 256-symbol alphabet. Max code length 12 bits.
 * Decode table: 4096 entries × 2 bytes = 8 KB (fits in L1).
 * ═══════════════════════════════════════════════════════════════ */

#define VV_HUF_MAX_BITS   12
#define VV_HUF_TABLE_SIZE (1 << VV_HUF_MAX_BITS)

typedef struct {
    uint8_t  lengths[256];            /* Code lengths per symbol */
    uint16_t codes[256];              /* Canonical codes (for encoding) */
    /* Decode table: entry = (symbol << 8) | num_bits */
    uint16_t decode[VV_HUF_TABLE_SIZE];
} vv_huffman_t;

/* ═══════════════════════════════════════════════════════════════
 * ENCODER/DECODER OPTIONS
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    vv_mode_t mode;
    uint8_t   window_log;    /* 0 = auto (20 for balanced, 24 for extreme) */
    int       checksum;      /* 1 = compute XXH64 */
    int       verbose;
} vv_options_t;

static inline void vv_default_options(vv_options_t *o) {
    o->mode = VV_MODE_BALANCED;
    o->window_log = 0;
    o->checksum = 1;
    o->verbose = 0;
}

/* ═══════════════════════════════════════════════════════════════
 * PUBLIC API
 * ═══════════════════════════════════════════════════════════════ */

/* Compress src[0..src_len-1] into dst[0..dst_cap-1].
 * Returns compressed size, or negative error code. */
int64_t vv_compress(const uint8_t *src, size_t src_len,
                    uint8_t *dst, size_t dst_cap,
                    const vv_options_t *opts);

/* Decompress src[0..src_len-1] into dst[0..dst_cap-1].
 * Returns decompressed size, or negative error code. */
int64_t vv_decompress(const uint8_t *src, size_t src_len,
                      uint8_t *dst, size_t dst_cap);

/* Compute upper bound on compressed size for src_len input bytes. */
size_t vv_compress_bound(size_t src_len);

/* ═══════════════════════════════════════════════════════════════
 * INTERNAL HELPERS (shared across modules)
 * ═══════════════════════════════════════════════════════════════ */

/* XXH64 hash (simplified, for checksum) */
/* VAPTVUPT: vv_xxh64 aliased to zupt_xxh64 (avoid duplicate symbol) */
#define vv_xxh64 zupt_xxh64

/* Hash function for matcher */
static inline uint32_t vv_hash4(const uint8_t *p) {
    uint32_t v;
    __builtin_memcpy(&v, p, 4);
    return (v * 2654435761u) >> (32 - VV_HC_BITS);
}

/* Read/write little-endian helpers */
static inline uint16_t vv_read16(const uint8_t *p) {
    uint16_t v; __builtin_memcpy(&v, p, 2); return v;
}
static inline uint32_t vv_read32(const uint8_t *p) {
    uint32_t v; __builtin_memcpy(&v, p, 4); return v;
}
static inline void vv_write16(uint8_t *p, uint16_t v) {
    __builtin_memcpy(p, &v, 2);
}
static inline void vv_write32(uint8_t *p, uint32_t v) {
    __builtin_memcpy(p, &v, 4);
}

/* ═══════════════════════════════════════════════════════════════
 * SIMD COPY HELPERS (declared here, defined in vv_simd.c)
 * ═══════════════════════════════════════════════════════════════ */

/* Copy exactly n bytes, may over-read/write by up to 32 bytes.
 * Caller must ensure sufficient slack in destination. */
void vv_copy_fast(uint8_t *dst, const uint8_t *src, size_t n);

/* Copy match with overlap handling (offset may be < copy length). */
void vv_copy_match(uint8_t *dst, uint32_t offset, size_t length);

#ifdef __cplusplus
}
#endif
#endif /* VAPTVUPT_H */
