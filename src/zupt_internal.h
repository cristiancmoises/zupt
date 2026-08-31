/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef ZUPT_INTERNAL_H
#define ZUPT_INTERNAL_H

#include "zupt.h"

/* Keep the published 5.2.1 option layout intact. The high bit is private to
 * the CLI/read path; ordinary nonzero verbose values retain their behavior. */
#define ZUPT_INTERNAL_ALLOW_LEGACY_NO_AIT 0x40000000

static inline void zupt_internal_set_verbose(zupt_options_t *options) {
    options->verbose |= 1;
}

static inline int zupt_internal_verbose(const zupt_options_t *options) {
    return options &&
           (options->verbose & ~ZUPT_INTERNAL_ALLOW_LEGACY_NO_AIT) != 0;
}

static inline void zupt_internal_allow_legacy_no_ait(
        zupt_options_t *options) {
    options->verbose |= ZUPT_INTERNAL_ALLOW_LEGACY_NO_AIT;
}

static inline int zupt_internal_legacy_no_ait_allowed(
        const zupt_options_t *options) {
    if (!options) return 0;
    int value = options->verbose;
    return (value & ZUPT_INTERNAL_ALLOW_LEGACY_NO_AIT) != 0 &&
           (value & ~(ZUPT_INTERNAL_ALLOW_LEGACY_NO_AIT | 1)) == 0;
}

/* A negative encoded capacity records an incomplete collection without
 * enlarging the published zupt_filelist_t structure. */
static inline int zupt_internal_filelist_failed(
        const zupt_filelist_t *filelist) {
    return filelist && filelist->capacity < 0;
}

static inline void zupt_internal_filelist_mark_failed(
        zupt_filelist_t *filelist) {
    if (filelist && filelist->capacity >= 0)
        filelist->capacity = -filelist->capacity - 1;
}

int zupt_dedup_lookup_secure(
    zupt_dedup_ctx_t *context, uint64_t fingerprint,
    const uint8_t digest[ZUPT_DEDUP_DIGEST_SIZE],
    uint64_t *reference_offset, uint32_t *reference_size,
    uint64_t *reference_aad_sequence);
int zupt_dedup_insert_secure(
    zupt_dedup_ctx_t *context, uint64_t fingerprint,
    const uint8_t digest[ZUPT_DEDUP_DIGEST_SIZE],
    uint64_t block_offset, uint32_t block_size,
    uint64_t block_aad_sequence);

#endif
