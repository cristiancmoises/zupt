/*
 * VaptVupt — ZUPT Integration API Implementation
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 *
 * ZUPT-COMPAT: thin wrapper over vv_compress/vv_decompress with
 * backup-optimized defaults for VaptVupt 2.65.0.
 *
 * Defaults applied here (per ZUPT_INTEGRATION.md, Sprint 122):
 *   - opts.checksum = 0      (ZUPT's HMAC-SHA256 / AES-GCM-SIV outer
 *                             already authenticates the compressed
 *                             bytes; XXH64 footer is redundant work
 *                             and saves ~10% encode time)
 *   - opts.format_v2 = 0     (AUTO). Since codec v2.61.0 the encoder
 *                             auto-enables min_match=3 ('T' blocks) for
 *                             binary-detected input and keeps 'S' blocks
 *                             for text. FORCING format_v2=1 routes text
 *                             through the binary/greedy path and HALVES the
 *                             extreme-mode ratio (text 7.6x -> 3.7x,
 *                             measured on codec 2.65.0); auto keeps the
 *                             optimal parser on text and still wins on
 *                             binary. Never force it here.
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
#include <stdlib.h>
#include <string.h>

int64_t vvz_compress(const uint8_t *src, size_t src_len,
                     uint8_t *dst, size_t dst_cap, int level) {
    vv_options_t opts;
    vv_default_options(&opts);
    opts.checksum = 0;     /* outer ZUPT MAC authenticates compressed bytes */
    opts.compat_v246_5_decoder = 0;  /* allow 4-stream Huffman literal coding */

    if (level <= 2) {
        opts.mode = VV_MODE_ULTRA_FAST;
        /* ULTRA_FAST + format_v2 is NOT in VaptVupt's tested matrix
         * (test_zupt_integration.c only validates format_v2 with
         * EXTREME/BALANCED). The combination produces output the decoder
         * rejects with VV_ERR_OVERFLOW. Stay on the v1 frame for ULTRA_FAST. */
        opts.format_v2 = 0;
    } else if (level <= 7) {
        opts.mode = VV_MODE_BALANCED;
        opts.format_v2 = 0;  /* AUTO: v2 for binary, optimal 'S' for text.
                              * Forcing v2 halves text ratio — see header. */
        opts.filter_auto = 1; /* BCJ on recognised ELF/PE/Mach-O input
                               * (codec 2.55.0): no-op on everything else.
                               * Blocks where a filter fired need a
                               * v2.54.0+ decoder (tool >= 3.9.0). */
    } else {
        opts.mode = VV_MODE_EXTREME;
        opts.format_v2 = 0;  /* AUTO (see BALANCED / header note) */
        opts.filter_auto = 1; /* see BALANCED note above */
    }

    /* Auto window: let adaptive selection choose wlog */
    opts.window_log = 0;

    int64_t csz = vv_compress(src, src_len, dst, dst_cap, &opts);
    if (csz <= 0)
        return csz;

    /* F-16 (v3.9.0): read-back self-check. The engine has produced, on
     * real machine-code content under specific mode x window combinations,
     * streams its own decoder rejects (observed: EXTREME + forced
     * window_log=20, and BALANCED + auto window, both on the same 3.5 MiB
     * ELF slice; reproducible on codec 2.53.3 and 2.60.4 alike). For a
     * backup tool a block that cannot be read back is data loss at
     * creation time, so every compressed block is decoded and compared
     * before it is accepted. On any mismatch this returns -1 and the
     * caller's existing fallback stores the block uncompressed instead.
     * Cost: one decompress per block (~12 ms per 4 MiB at ~300 MB/s),
     * small next to BALANCED/EXTREME encode cost; correctness is not
     * negotiable. */
    uint8_t *chk = (uint8_t *)malloc(src_len + 64 /* SIMD over-store slack,
                                                     mirrors ZUPT_VV_DECODE_SLACK */);
    if (!chk)
        return -1;  /* cannot prove the block reads back -> fail closed */
    int64_t dsz = vv_decompress_flags(dst, (size_t)csz, chk, src_len + 64,
                                      VV_DECOMPRESS_SKIP_CHECKSUM);
    int ok = (dsz == (int64_t)src_len) && (memcmp(chk, src, src_len) == 0);
    free(chk);
    return ok ? csz : -1;
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
