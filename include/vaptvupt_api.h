/* VaptVupt codec — originally Apache-2.0 by Cristian Cezar Moisés
 * Integrated into Zupt — MIT License
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: MIT AND Apache-2.0
 */

/*
 * VaptVupt — Zupt Integration API
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 Cristian.
 *
 * ZUPT-COMPAT: This is the API that Zupt calls. It wraps the internal
 * VaptVupt API with sensible defaults for backup workloads:
 *   - Checksum always enabled (data integrity is critical for backups)
 *   - Adaptive window selection (auto-detect optimal wlog per file)
 *   - Level maps to mode: 1=fast, 5=balanced, 9=extreme
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
