/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 * ZUPT v2.1.5 — Block-Level Deduplication
 * Copyright (c) 2026 Cristian Cezar Moises — AGPL-3.0-or-later
 *
 * Eliminates redundant data blocks before compression using XXH64
 * fingerprinting with an independent SHA-256/128 verification on match.
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
 *   - XXH64 is not collision-resistant, so a reference also requires an
 *     independent 128-bit prefix of SHA-256 to match.
 *   - Hash table memory is securely wiped on free.
 *   - Dedup operates on plaintext before encryption.
 *   - References are intra-archive offsets only.
 */
#include "zupt.h"
#include "zupt_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Hash table entry */
typedef struct {
    uint64_t fingerprint;   /* XXH64 of the block content */
    uint64_t block_offset;  /* File offset where the block was written */
    uint8_t digest[ZUPT_DEDUP_DIGEST_SIZE]; /* independent SHA-256 prefix */
    uint32_t block_size;    /* Uncompressed size of the block */
    uint32_t occupied;      /* 0 = empty, 1 = occupied */
    uint64_t aad_seq;       /* Logical position used to authenticate DATA */
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
 * XXH64 selects the probe chain; the independent SHA-256 prefix must also
 * match before the stored offset is returned.
 */
int zupt_dedup_lookup_secure(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                             const uint8_t digest[ZUPT_DEDUP_DIGEST_SIZE],
                             uint64_t *ref_offset, uint32_t *ref_size,
                             uint64_t *ref_aad_seq) {
    if (!ctx || !ctx->table || !digest) return 0;

    uint32_t idx = (uint32_t)(fingerprint % ctx->capacity);
    for (uint32_t i = 0; i < 64; i++) {  /* Max 64 probes */
        uint32_t slot = (idx + i) % ctx->capacity;
        zupt_dedup_entry_t *e = &ctx->table[slot];
        if (!e->occupied) return 0;  /* Empty slot = not found */
        if (e->fingerprint == fingerprint &&
            memcmp(e->digest, digest, ZUPT_DEDUP_DIGEST_SIZE) == 0) {
            if (ref_offset) *ref_offset = e->block_offset;
            if (ref_size) *ref_size = e->block_size;
            if (ref_aad_seq) *ref_aad_seq = e->aad_seq;
            return 1;
        }
    }
    return 0;  /* Probe limit reached */
}

/*
 * Insert a block into the dedup index.
 * Returns 1 on success, 0 if table is full.
 */
int zupt_dedup_insert_secure(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                             const uint8_t digest[ZUPT_DEDUP_DIGEST_SIZE],
                             uint64_t block_offset, uint32_t block_size,
                             uint64_t block_aad_seq) {
    if (!ctx || !ctx->table || !digest) return 0;
    if (ctx->count >= ctx->capacity * 3 / 4) return 0;  /* 75% load factor limit */

    uint32_t idx = (uint32_t)(fingerprint % ctx->capacity);
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t slot = (idx + i) % ctx->capacity;
        zupt_dedup_entry_t *e = &ctx->table[slot];
        if (!e->occupied) {
            e->fingerprint = fingerprint;
            e->block_offset = block_offset;
            memcpy(e->digest, digest, ZUPT_DEDUP_DIGEST_SIZE);
            e->block_size = block_size;
            e->aad_seq = block_aad_seq;
            e->occupied = 1;
            ctx->count++;
            return 1;
        }
    }
    return 0;  /* Probe limit */
}

/* Preserve the published 5.2.1 symbols and signatures. First-party archive
 * writers use the secure variants above with an independent digest. */
int zupt_dedup_lookup(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                      uint64_t *ref_offset, uint32_t *ref_size) {
    static const uint8_t legacy_digest[ZUPT_DEDUP_DIGEST_SIZE] = {0};
    return zupt_dedup_lookup_secure(ctx, fingerprint, legacy_digest,
                                    ref_offset, ref_size, NULL);
}

int zupt_dedup_insert(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                      uint64_t block_offset, uint32_t block_size) {
    static const uint8_t legacy_digest[ZUPT_DEDUP_DIGEST_SIZE] = {0};
    return zupt_dedup_insert_secure(ctx, fingerprint, legacy_digest,
                                    block_offset, block_size, 0);
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

/* New encrypted archives authenticate the otherwise mutable reference offset.
 * The logical size/checksum remain in the frame preface and are included in
 * v1.6 preface AAD. The encrypted payload binds both the intra-archive offset
 * and the logical AAD sequence used by the referenced DATA frame; the
 * reference frame itself uses its own logical position as AAD. */
int zupt_dedup_write_ref_secure(FILE *out, uint64_t ref_offset,
                                uint32_t orig_size, uint64_t orig_checksum,
                                uint64_t current_aad_seq,
                                uint64_t referenced_aad_seq,
                                const zupt_keyring_t *keyring) {
    uint8_t reference[16];
    zupt_le64_put(reference, ref_offset);
    zupt_le64_put(reference + 8, referenced_aad_seq);
    const uint8_t *payload = reference;
    size_t payload_size = keyring && keyring->active ? sizeof(reference) : 8u;
    uint16_t block_flags = 0;
    uint8_t *encrypted = NULL;

    if (keyring && keyring->active) {
        size_t encrypted_size = 0;
        if (keyring->use_preface_aad) {
            uint8_t preface[ZUPT_PREFACE_AAD_LEN];
            uint64_t predicted_size = 16u + sizeof(reference) + 32u;
            zupt_serialize_preface_aad_scalars(
                ZUPT_BLOCK_DEDUP_REF, ZUPT_CODEC_STORE,
                ZUPT_BFLAG_ENCRYPTED, orig_size, predicted_size,
                orig_checksum, preface);
            encrypted = zupt_encrypt_buffer_aad(
                keyring, reference, sizeof(reference), current_aad_seq,
                preface, sizeof(preface), &encrypted_size);
            zupt_secure_wipe(preface, sizeof(preface));
        } else {
            encrypted = zupt_encrypt_buffer(keyring, reference,
                                             sizeof(reference), current_aad_seq,
                                             &encrypted_size);
        }
        if (!encrypted) return -1;
        payload = encrypted;
        payload_size = encrypted_size;
        block_flags = ZUPT_BFLAG_ENCRYPTED;
    }

    zupt_w8(out, ZUPT_BLOCK_MAGIC_0);
    zupt_w8(out, ZUPT_BLOCK_MAGIC_1);
    zupt_w8(out, ZUPT_BLOCK_DEDUP_REF);
    zupt_w16le(out, ZUPT_CODEC_STORE);
    zupt_w16le(out, block_flags);
    zupt_write_varint(out, (uint64_t)orig_size);
    zupt_write_varint(out, payload_size);
    zupt_w64le(out, orig_checksum);
    int result = fwrite(payload, 1, payload_size, out) == payload_size &&
                 !ferror(out) ? 0 : -1;
    free(encrypted);
    return result;
}

zupt_error_t zupt_dedup_read_ref(const zupt_block_t *block,
                                 const zupt_keyring_t *keyring,
                                 int require_authentication,
                                 uint64_t current_aad_seq,
                                 uint64_t *ref_offset,
                                 uint64_t *referenced_aad_seq) {
    if (!block || !ref_offset || !referenced_aad_seq ||
        block->block_type != ZUPT_BLOCK_DEDUP_REF ||
        block->codec_id != ZUPT_CODEC_STORE || !block->payload)
        return ZUPT_ERR_CORRUPT;

    const uint8_t *payload = block->payload;
    size_t payload_size = (size_t)block->compressed_size;
    uint8_t *plain = NULL;

    if (require_authentication) {
        if (!(block->block_flags & ZUPT_BFLAG_ENCRYPTED) ||
            !keyring || !keyring->active)
            return ZUPT_ERR_AUTH_FAIL;
        size_t plain_size = 0;
        if (keyring->use_preface_aad) {
            uint8_t preface[ZUPT_PREFACE_AAD_LEN];
            zupt_serialize_preface_aad_scalars(
                block->block_type, block->codec_id, block->block_flags,
                block->uncompressed_size, block->compressed_size,
                block->checksum, preface);
            plain = zupt_decrypt_buffer_aad(
                keyring, payload, payload_size, current_aad_seq,
                preface, sizeof(preface), &plain_size);
            zupt_secure_wipe(preface, sizeof(preface));
        } else {
            plain = zupt_decrypt_buffer(keyring, payload, payload_size,
                                        current_aad_seq,
                                        &plain_size);
        }
        if (!plain) return ZUPT_ERR_AUTH_FAIL;
        if (plain_size != 16) {
            zupt_secure_wipe(plain, plain_size);
            free(plain);
            return ZUPT_ERR_CORRUPT;
        }
        payload = plain;
        payload_size = plain_size;
    } else if (block->block_flags != 0 || payload_size != 8) {
        return ZUPT_ERR_CORRUPT;
    }

    if ((!require_authentication && payload_size != 8) ||
        (require_authentication && payload_size != 16)) {
        free(plain);
        return ZUPT_ERR_CORRUPT;
    }
    *ref_offset = zupt_le64_get(payload);
    *referenced_aad_seq = require_authentication
        ? zupt_le64_get(payload + 8) : 0;
    if (plain) {
        zupt_secure_wipe(plain, payload_size);
        free(plain);
    }
    return ZUPT_OK;
}
