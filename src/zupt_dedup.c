/*
 * Zupt v2.1.5 — Block-Level Deduplication
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moises — AGPL-3.0-or-later (commercial: sac@securityops.co)
 *
 * Eliminates redundant data blocks before compression using XXH64
 * fingerprinting with full content verification on match.
 *
 * Architecture:
 *   Source → XXH64 fingerprint → Hash table lookup → Match?
 *     YES → write DEDUP_REF block (8 bytes: offset of original)
 *     NO  → write normal DATA block, insert into hash table
 *
 * The hash table uses open-addressing with linear probing,
 * capped at ZUPT_DEDUP_MAX_ENTRIES (2M entries = ~48MB RAM).
 *
 * Security:
 *   - XXH64 is not collision-resistant, so we verify full content
 *     on hash match before emitting a reference.
 *   - Hash table memory is securely wiped on free.
 *   - Dedup operates on plaintext before encryption.
 *   - References are intra-archive offsets only.
 */
#include "zupt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Hash table entry */
typedef struct {
    uint64_t fingerprint;   /* XXH64 of the block content */
    uint64_t block_offset;  /* File offset where the block was written */
    uint32_t block_size;    /* Uncompressed size of the block */
    uint32_t occupied;      /* 0 = empty, 1 = occupied */
} zupt_dedup_entry_t;

/* Dedup context */
struct zupt_dedup_ctx {
    zupt_dedup_entry_t *table;
    uint32_t capacity;
    uint32_t count;
    /* Stats */
    uint64_t blocks_seen;
    uint64_t blocks_deduped;
    uint64_t bytes_saved;
};

zupt_dedup_ctx_t *zupt_dedup_init(void) {
    zupt_dedup_ctx_t *ctx = (zupt_dedup_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->capacity = ZUPT_DEDUP_MAX_ENTRIES;
    ctx->table = (zupt_dedup_entry_t *)calloc(ctx->capacity, sizeof(zupt_dedup_entry_t));
    if (!ctx->table) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

void zupt_dedup_free(zupt_dedup_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->table) {
        /* Secure wipe — table contains fingerprints of potentially sensitive data */
        volatile uint8_t *p = (volatile uint8_t *)ctx->table;
        size_t len = (size_t)ctx->capacity * sizeof(zupt_dedup_entry_t);
        for (size_t i = 0; i < len; i++) p[i] = 0;
        free(ctx->table);
    }
    free(ctx);
}

/*
 * Look up a block in the dedup index.
 * Returns 1 if a match is found (sets *ref_offset), 0 if not found.
 *
 * The caller must verify content equality before trusting the match
 * (XXH64 is fast but not collision-resistant). The content verification
 * is done by the caller who has access to the archive FILE* to seek
 * and re-read the original block.
 */
int zupt_dedup_lookup(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                      uint64_t *ref_offset, uint32_t *ref_size) {
    if (!ctx || !ctx->table) return 0;

    uint32_t idx = (uint32_t)(fingerprint % ctx->capacity);
    for (uint32_t i = 0; i < 64; i++) {  /* Max 64 probes */
        uint32_t slot = (idx + i) % ctx->capacity;
        zupt_dedup_entry_t *e = &ctx->table[slot];
        if (!e->occupied) return 0;  /* Empty slot = not found */
        if (e->fingerprint == fingerprint) {
            if (ref_offset) *ref_offset = e->block_offset;
            if (ref_size) *ref_size = e->block_size;
            return 1;
        }
    }
    return 0;  /* Probe limit reached */
}

/*
 * Insert a block into the dedup index.
 * Returns 1 on success, 0 if table is full.
 */
int zupt_dedup_insert(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                      uint64_t block_offset, uint32_t block_size) {
    if (!ctx || !ctx->table) return 0;
    if (ctx->count >= ctx->capacity * 3 / 4) return 0;  /* 75% load factor limit */

    uint32_t idx = (uint32_t)(fingerprint % ctx->capacity);
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t slot = (idx + i) % ctx->capacity;
        zupt_dedup_entry_t *e = &ctx->table[slot];
        if (!e->occupied) {
            e->fingerprint = fingerprint;
            e->block_offset = block_offset;
            e->block_size = block_size;
            e->occupied = 1;
            ctx->count++;
            return 1;
        }
    }
    return 0;  /* Probe limit */
}

void zupt_dedup_record_hit(zupt_dedup_ctx_t *ctx, uint64_t saved_bytes) {
    if (!ctx) return;
    ctx->blocks_deduped++;
    ctx->bytes_saved += saved_bytes;
}

void zupt_dedup_record_block(zupt_dedup_ctx_t *ctx) {
    if (!ctx) return;
    ctx->blocks_seen++;
}

void zupt_dedup_stats(const zupt_dedup_ctx_t *ctx,
                      uint64_t *blocks_seen, uint64_t *blocks_deduped,
                      uint64_t *bytes_saved) {
    if (!ctx) {
        if (blocks_seen) *blocks_seen = 0;
        if (blocks_deduped) *blocks_deduped = 0;
        if (bytes_saved) *bytes_saved = 0;
        return;
    }
    if (blocks_seen) *blocks_seen = ctx->blocks_seen;
    if (blocks_deduped) *blocks_deduped = ctx->blocks_deduped;
    if (bytes_saved) *bytes_saved = ctx->bytes_saved;
}

/*
 * Write a dedup reference block to the archive.
 * The ref block stores the offset of the original data block.
 * On restore, the reader seeks to that offset, reads the original
 * block, and decompresses it.
 *
 * Format: standard block header with type=DEDUP_REF, codec=STORE,
 * uncompressed_size = original block's uncompressed size,
 * compressed_size = 8 (just the offset),
 * checksum = original block's checksum,
 * payload = 8-byte LE offset.
 */
int zupt_dedup_write_ref(FILE *out, uint64_t ref_offset,
                         uint32_t orig_size, uint64_t orig_checksum) {
    uint8_t payload[8];
    zupt_le64_put(payload, ref_offset);

    zupt_w8(out, ZUPT_BLOCK_MAGIC_0);
    zupt_w8(out, ZUPT_BLOCK_MAGIC_1);
    zupt_w8(out, ZUPT_BLOCK_DEDUP_REF);
    zupt_w16le(out, ZUPT_CODEC_STORE);
    zupt_w16le(out, 0);  /* flags */
    zupt_write_varint(out, (uint64_t)orig_size);
    zupt_write_varint(out, 8);  /* compressed_size = 8 bytes (the offset) */
    zupt_w64le(out, orig_checksum);
    if (fwrite(payload, 1, 8, out) != 8) return -1;
    return 0;
}
