/*
 * VaptVupt — VaptVupt Integration API
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 Cristian.
 *
 * EMBED-COMPAT: This is the API that a host application calls. It wraps the internal
 * VaptVupt API with the ZUPT backup policy:
 *   - Internal XXH64 disabled; ZUPT records its own per-block XXH64, and
 *     encrypted modes additionally authenticate ciphertext and metadata
 *   - Adaptive window selection and automatic executable filtering
 *   - Levels 1-2 FAST, 3-7 balanced, and 8-9 extreme
 *   - Every encoded block is decoded and compared before it is accepted
 *
 * Usage:
 *   size_t bound = vvz_compress_bound(src_len);
 *   uint8_t *dst = malloc(bound);
 *   int64_t csz = vvz_compress(src, src_len, dst, bound, 5);
 *   int64_t dsz = vvz_decompress(dst, csz, out, out_cap);
 */
#ifndef VAPTVUPT_API_H
#define VAPTVUPT_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compress src into dst. Returns compressed size or negative error code.
 * level: 1 = fast (max speed), 5 = balanced (default), 9 = extreme (max ratio) */
int64_t vvz_compress(const uint8_t *src, size_t src_len,
                     uint8_t *dst, size_t dst_cap, int level);

/* Decompress src into dst. Returns decompressed size or negative error code. */
int64_t vvz_decompress(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap);

/* Upper bound on compressed size for a given input length. */
size_t vvz_compress_bound(size_t src_len);

#ifdef __cplusplus
}
#endif
#endif /* VAPTVUPT_API_H */
