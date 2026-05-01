/*
 * VaptVupt — Zupt Integration API Implementation
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 Cristian.
 *
 * ZUPT-COMPAT: thin wrapper over vv_compress/vv_decompress with
 * backup-optimized defaults. Decode speed prioritized over encode.
 */

#include "vaptvupt_api.h"
#include "vaptvupt.h"

int64_t vvz_compress(const uint8_t *src, size_t src_len,
                     uint8_t *dst, size_t dst_cap, int level) {
    vv_options_t opts;
    vv_default_options(&opts);
    opts.checksum = 1;     /* frame-level integrity */
    opts.format_v2 = 1;    /* 4-7% better binary ratio (v2.33.0+ decoders) */

    if (level <= 2) {
        opts.mode = VV_MODE_ULTRA_FAST;
    } else if (level <= 7) {
        opts.mode = VV_MODE_BALANCED;
    } else {
        opts.mode = VV_MODE_EXTREME;
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
