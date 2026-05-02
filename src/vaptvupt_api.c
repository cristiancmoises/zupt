/*
 * VaptVupt — Zupt Integration API Implementation
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 *
 * ZUPT-COMPAT: thin wrapper over vv_compress/vv_decompress with
 * backup-optimized defaults for VaptVupt 2.48.2.
 *
 * Defaults applied here (per ZUPT_INTEGRATION.md, Sprint 122):
 *   - opts.checksum = 0      (Zupt's HMAC-SHA256 / AES-GCM-SIV outer
 *                             already authenticates the compressed
 *                             bytes; XXH64 footer is redundant work
 *                             and saves ~10% encode time)
 *   - opts.format_v2 = 1     (4-7% better binary ratio; v2.33.0+
 *                             decoders read v2 frames transparently)
 *   - VV_DECOMPRESS_SKIP_CHECKSUM on decode (matched pair to
 *                             checksum=0 on encode; saves ~30% on real
 *                             fixtures, 2-5x on AEAD-wrapped data)
 *   - opts.compat_v246_5_decoder = 0 (allow lit_fmt=4 / 4-stream
 *                             Huffman; we control both encoder and
 *                             decoder versions in-tree, so we always
 *                             have v2.47+ on the decode side)
 */

#include "vaptvupt_api.h"
#include "vaptvupt.h"

int64_t vvz_compress(const uint8_t *src, size_t src_len,
                     uint8_t *dst, size_t dst_cap, int level) {
    vv_options_t opts;
    vv_default_options(&opts);
    opts.checksum = 0;     /* outer Zupt MAC authenticates compressed bytes */
    opts.compat_v246_5_decoder = 0;  /* allow 4-stream Huffman literal coding */

    if (level <= 2) {
        opts.mode = VV_MODE_ULTRA_FAST;
        /* ULTRA_FAST + format_v2 is NOT in VaptVupt 2.48.2's tested matrix
         * (test_zupt_integration.c only validates format_v2 with
         * EXTREME/BALANCED). The combination produces output the decoder
         * rejects with VV_ERR_OVERFLOW. Stay on the v1 frame for ULTRA_FAST. */
        opts.format_v2 = 0;
    } else if (level <= 7) {
        opts.mode = VV_MODE_BALANCED;
        opts.format_v2 = 1;  /* 4-7% better binary ratio (v2.33.0+ decoders) */
    } else {
        opts.mode = VV_MODE_EXTREME;
        opts.format_v2 = 1;  /* 4-7% better binary ratio (v2.33.0+ decoders) */
    }

    /* Auto window: let adaptive selection choose wlog */
    opts.window_log = 0;

    return vv_compress(src, src_len, dst, dst_cap, &opts);
}

int64_t vvz_decompress(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap) {
    /* Skip XXH64 verification — zupt's HMAC-SHA256 already authenticates */
    return vv_decompress_flags(src, src_len, dst, dst_cap,
                               VV_DECOMPRESS_SKIP_CHECKSUM);
}

size_t vvz_compress_bound(size_t src_len) {
    return vv_compress_bound(src_len);
}

/* ═══════════════════════════════════════════════════════════════
 * Frame metadata accessor
 * ═══════════════════════════════════════════════════════════════ */

int vv_get_frame_info(const uint8_t *src, size_t src_len,
                      vv_frame_info_t *info) {
    if (!src || !info) return VV_ERR_PARAM;
    if (src_len < sizeof(vv_frame_header_t)) return VV_ERR_CORRUPT;

    vv_frame_header_t fh;
    memcpy(&fh, src, sizeof(fh));
    if (fh.magic != VV_MAGIC) return VV_ERR_BAD_MAGIC;
    if (fh.version != 1) return VV_ERR_CORRUPT;

    info->version = fh.version;
    info->has_checksum = (fh.flags & 1) ? 1 : 0;
    info->mode_hint = fh.mode_hint;
    info->window_log = fh.window_log;
    info->content_size = fh.content_size;
    return VV_OK;
}
