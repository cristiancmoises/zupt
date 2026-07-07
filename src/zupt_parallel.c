/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 * ZUPT v0.6.0 — Parallel Compress / Decompress Pipeline
 *
 * Architecture: batch-parallel with persistent worker threads.
 *
 * Compression worker (one block):
 *   1. Read input from slot
 *   2. Compute XXH64 checksum of uncompressed data
 *   3. Compress (LZHP / LZH / LZ / Store fallback)
 *   4. Encrypt if keyring active (per-block nonce = base_nonce XOR block_seq)
 *   5. Store result in slot, set DONE
 *
 * Decompression worker (one block):
 *   1. If encrypted: verify HMAC FIRST, then decrypt (Encrypt-then-MAC)
 *   2. Decompress (codec-specific)
 *   3. Verify XXH64 checksum
 *   4. Store result in slot, set DONE
 *
 * Security invariants preserved:
 *   - HMAC verified BEFORE decryption in every worker
 *   - Per-block nonce = base_nonce XOR block_seq (unchanged, deterministic)
 *   - Keyring is read-only shared state (copied at context creation)
 *   - zupt_secure_wipe() called on any intermediate crypto buffers
 *   - No new global mutable state
 */
#include "zupt_parallel.h"
#include "vaptvupt.h"  /* VAPTVUPT: VaptVupt codec integration */
#include "vaptvupt_api.h"  /* F-16: single codec-option policy (vvz_*) */
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * WORKER: COMPRESS ONE BLOCK
 *
 * Identical logic to the single-threaded inner loop in zupt_format.c.
 * Each worker has its own stack-allocated compress buffer.
 * ═══════════════════════════════════════════════════════════════════ */

static void worker_compress(zpar_slot_t *slot, const zupt_keyring_t *kr) {
    const uint8_t *rbuf = slot->input;
    size_t nread = slot->input_len;
    int level = slot->level;
    uint16_t codec = slot->codec_id;

    /* Checksum of uncompressed data (per-block, for archive integrity) */
    slot->checksum = zupt_xxh64(rbuf, nread, 0);

    /* Allocate compress buffer */
    size_t cbuf_cap = zupt_lzh_bound(nread) + 512;
    uint8_t *cbuf = (uint8_t *)malloc(cbuf_cap);
    if (!cbuf) { slot->error = ZUPT_ERR_NOMEM; return; }

    size_t comp_size = 0;

    if (codec == ZUPT_CODEC_ZUPT_LZHP) {
        uint8_t pred[256];
        float benefit = zupt_predict_benefit(rbuf, nread);

        if (benefit > 0.03f && nread > 256) {
            zupt_predict_build(rbuf, nread, pred);
            uint8_t *transformed = (uint8_t *)malloc(nread);
            if (transformed) {
                zupt_predict_encode(rbuf, transformed, nread, pred);
                size_t lzh_cap = zupt_lzh_bound(nread);
                uint8_t *lzh_out = cbuf + 1 + 256;
                size_t lzh_size = zupt_lzh_compress(transformed, nread, lzh_out, lzh_cap, level);
                free(transformed);

                if (lzh_size > 0 && 1 + 256 + lzh_size < nread) {
                    cbuf[0] = 0x01;
                    memcpy(cbuf + 1, pred, 256);
                    comp_size = 1 + 256 + lzh_size;
                } else {
                    cbuf[0] = 0x00;
                    size_t plain = zupt_lzh_compress(rbuf, nread, cbuf + 1, lzh_cap, level);
                    if (plain > 0 && 1 + plain < nread)
                        comp_size = 1 + plain;
                }
            }
        } else {
            cbuf[0] = 0x00;
            size_t lzh_cap = zupt_lzh_bound(nread);
            size_t plain = zupt_lzh_compress(rbuf, nread, cbuf + 1, lzh_cap, level);
            if (plain > 0 && 1 + plain < nread)
                comp_size = 1 + plain;
        }
    } else if (codec == ZUPT_CODEC_ZUPT_LZH) {
        comp_size = zupt_lzh_compress(rbuf, nread, cbuf, zupt_lzh_bound(nread), level);
    } else if (codec == ZUPT_CODEC_ZUPT_LZ) {
        comp_size = zupt_lz_compress(rbuf, nread, cbuf, zupt_lz_bound(nread), level);
    }
    /* VAPTVUPT: VaptVupt codec in parallel compress worker.
     *
     * F-16 (v3.9.0): this worker previously built its own vv_options_t
     * and had drifted from the serial wrapper (forced window_log=20, a
     * different ULTRA_FAST cutoff, checksum=1, no format_v2, no BCJ, no
     * ULTRA_FAST/format_v2 gate). EXTREME + window_log=20 produced
     * blocks the decoder rejects on real ELF content — a corrupt archive
     * at creation time. Codec option policy now lives in exactly one
     * place: vvz_compress() (src/vaptvupt_api.c), which also self-checks
     * every produced block (decode + memcmp) and fails closed so the
     * caller falls back to STORE rather than ever writing an unreadable
     * block. Serial and parallel paths emit identical streams. */
    else if (codec == ZUPT_CODEC_VAPTVUPT) {
        size_t vv_cap = vvz_compress_bound(nread);
        uint8_t *vv_tmp = (uint8_t *)malloc(vv_cap);
        if (vv_tmp) {
            int64_t csz = vvz_compress(rbuf, nread, vv_tmp, vv_cap, level);
            if (csz > 0 && (size_t)csz < nread) {
                if ((size_t)csz <= cbuf_cap) {
                    memcpy(cbuf, vv_tmp, (size_t)csz);
                    comp_size = (size_t)csz;
                }
            }
            free(vv_tmp);
        }
    }

    /* Decide payload */
    const uint8_t *payload;
    size_t payload_size;
    if (comp_size == 0 || comp_size >= nread) {
        slot->actual_codec = ZUPT_CODEC_STORE;
        payload = rbuf;
        payload_size = nread;
    } else {
        slot->actual_codec = codec;
        payload = cbuf;
        payload_size = comp_size;
    }

    /* Encrypt if needed */
    slot->out_bflags = 0;
    if (kr && kr->active) {
        size_t enc_len;
        uint8_t *enc;
        /* F-09: when the archive uses AAD-preface mode, bind the per-block frame
         * preface into the MAC EXACTLY as the serial path does (zupt_format.c).
         * The extract side honours the archive's ZUPT_FLAG_AAD_PREFACE flag, so
         * if this worker skipped the preface every multithreaded encrypted block
         * would fail authentication and the archive would be unextractable. The
         * scalars mirror the serial call: predicted compressed_size is
         * nonce(16) + payload + hmac(32), block_flags is ENCRYPTED. */
        if (kr->use_preface_aad) {
            uint8_t preface[ZUPT_PREFACE_AAD_LEN];
            uint64_t predicted_csz = 16 + (uint64_t)payload_size + 32;
            zupt_serialize_preface_aad_scalars(
                ZUPT_BLOCK_DATA, slot->actual_codec, (uint16_t)ZUPT_BFLAG_ENCRYPTED,
                (uint64_t)nread, predicted_csz, slot->checksum, preface);
            enc = zupt_encrypt_buffer_aad(kr, payload, payload_size, slot->block_seq,
                                          preface, ZUPT_PREFACE_AAD_LEN, &enc_len);
            zupt_secure_wipe(preface, sizeof(preface));
        } else {
            enc = zupt_encrypt_buffer(kr, payload, payload_size, slot->block_seq, &enc_len);
        }
        if (!enc) { free(cbuf); slot->error = ZUPT_ERR_NOMEM; return; }
        /* Output is the encrypted payload (caller frees slot->output) */
        slot->output = enc;
        slot->output_len = enc_len;
        slot->out_bflags |= ZUPT_BFLAG_ENCRYPTED;
        free(cbuf);
    } else {
        /* Copy payload to output (cbuf may be stack of caller) */
        slot->output = (uint8_t *)malloc(payload_size);
        if (!slot->output) { free(cbuf); slot->error = ZUPT_ERR_NOMEM; return; }
        memcpy(slot->output, payload, payload_size);
        slot->output_len = payload_size;
        free(cbuf);
    }

    slot->error = ZUPT_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * WORKER: DECOMPRESS ONE BLOCK
 *
 * Security: HMAC verified BEFORE any decryption (Encrypt-then-MAC).
 * ═══════════════════════════════════════════════════════════════════ */

static void worker_decompress(zpar_slot_t *slot, const zupt_keyring_t *kr) {
    const uint8_t *comp_data = slot->input;
    size_t comp_len = slot->input_len;
    uint8_t *dec_payload = NULL;

    /* Validate */
    if (!comp_data && comp_len > 0) { slot->error = ZUPT_ERR_CORRUPT; return; }
    if (slot->uncomp_size > ZUPT_MAX_BLOCK_SZ) { slot->error = ZUPT_ERR_OVERFLOW; return; }

    /* SECURITY: in an encrypted archive every block MUST be encrypted. The
     * per-block ENCRYPTED flag is not covered by the archive-integrity
     * trailer, so without this gate an attacker could clear the flag on a
     * forged STORE block and inject attacker-chosen plaintext that passes
     * only the keyless XXH64 — an authentication bypass. Mirror the
     * single-threaded decompress_block fail-closed behaviour. */
    if (kr && kr->active && !(slot->block_flags & ZUPT_BFLAG_ENCRYPTED)) {
        slot->error = ZUPT_ERR_AUTH_FAIL; return;
    }

    /* Decrypt if encrypted — HMAC verified inside the decrypt call (before
     * decryption). Must mirror the compress worker and the serial
     * decompress_block: when the archive uses AAD-preface mode, rebuild the
     * canonical preface from this block's stored header fields and bind it into
     * the MAC, otherwise a multithreaded extract of a preface-bound archive
     * fails to authenticate every block. */
    if (slot->block_flags & ZUPT_BFLAG_ENCRYPTED) {
        if (!kr || !kr->active) { slot->error = ZUPT_ERR_AUTH_FAIL; return; }
        size_t dec_len;
        if (kr->use_preface_aad) {
            uint8_t preface[ZUPT_PREFACE_AAD_LEN];
            zupt_serialize_preface_aad_scalars(
                ZUPT_BLOCK_DATA, slot->codec_id, slot->block_flags,
                slot->uncomp_size, (uint64_t)comp_len, slot->stored_checksum, preface);
            dec_payload = zupt_decrypt_buffer_aad(kr, comp_data, comp_len, slot->block_seq,
                                                  preface, ZUPT_PREFACE_AAD_LEN, &dec_len);
            zupt_secure_wipe(preface, sizeof(preface));
        } else {
            dec_payload = zupt_decrypt_buffer(kr, comp_data, comp_len, slot->block_seq, &dec_len);
        }
        if (!dec_payload) { slot->error = ZUPT_ERR_AUTH_FAIL; return; }
        comp_data = dec_payload;
        comp_len = dec_len;
    }

    size_t olen = (size_t)slot->uncomp_size;
    if (olen == 0) {
        slot->output = NULL;
        slot->output_len = 0;
        free(dec_payload);
        slot->error = ZUPT_OK;
        return;
    }

    /* Over-allocate by ZUPT_VV_DECODE_SLACK for the VaptVupt AVX2 decode
     * over-copy (see zupt.h). olen still tracks the true uncompressed
     * size for the XXH64 verify and the returned output_len. */
    uint8_t *out = (uint8_t *)malloc(olen + ZUPT_VV_DECODE_SLACK);
    if (!out) { free(dec_payload); slot->error = ZUPT_ERR_NOMEM; return; }

    zupt_error_t result = ZUPT_OK;
    uint16_t codec = slot->codec_id;

    if (codec == ZUPT_CODEC_STORE) {
        if (comp_len < olen) result = ZUPT_ERR_CORRUPT;
        else memcpy(out, comp_data, olen);
    } else if (codec == ZUPT_CODEC_ZUPT_LZ) {
        size_t r = zupt_lz_decompress(comp_data, comp_len, out, olen);
        if (r != olen) result = ZUPT_ERR_CORRUPT;
    } else if (codec == ZUPT_CODEC_ZUPT_LZH) {
        size_t r = zupt_lzh_decompress(comp_data, comp_len, out, olen);
        if (r != olen) result = ZUPT_ERR_CORRUPT;
    } else if (codec == ZUPT_CODEC_ZUPT_LZHP) {
        if (comp_len < 1) { result = ZUPT_ERR_CORRUPT; goto done; }
        uint8_t pflag = comp_data[0];
        int pred_active = (pflag & 0x01);
        size_t hdr_size = pred_active ? 257 : 1;
        uint8_t pred[256];
        if (pred_active) {
            if (comp_len < 257) { result = ZUPT_ERR_CORRUPT; goto done; }
            memcpy(pred, comp_data + 1, 256);
        }
        if (comp_len <= hdr_size) { result = ZUPT_ERR_CORRUPT; goto done; }
        const uint8_t *lzh_data = comp_data + hdr_size;
        size_t lzh_len = comp_len - hdr_size;
        if (pred_active) {
            uint8_t *temp = (uint8_t *)malloc(olen);
            if (!temp) { result = ZUPT_ERR_NOMEM; goto done; }
            size_t r = zupt_lzh_decompress(lzh_data, lzh_len, temp, olen);
            if (r != olen) { free(temp); result = ZUPT_ERR_CORRUPT; goto done; }
            zupt_predict_decode(temp, out, olen, pred);
            free(temp);
        } else {
            size_t r = zupt_lzh_decompress(lzh_data, lzh_len, out, olen);
            if (r != olen) result = ZUPT_ERR_CORRUPT;
        }
    }
    /* VAPTVUPT: VaptVupt codec in parallel decompress worker */
    else if (codec == ZUPT_CODEC_VAPTVUPT) {
        /* Pass padded capacity (olen + slack) for the AVX2 over-copy;
         * require the returned size to equal the true olen. */
        int64_t dsz = vv_decompress(comp_data, comp_len, out,
                                    olen + ZUPT_VV_DECODE_SLACK);
        if (dsz < 0 || (size_t)dsz != olen) result = ZUPT_ERR_CORRUPT;
    } else {
        result = ZUPT_ERR_UNSUPPORTED;
    }

done:
    free(dec_payload);
    if (result != ZUPT_OK) { free(out); slot->output = NULL; slot->output_len = 0; slot->error = result; return; }

    /* Verify checksum */
    uint64_t ck = zupt_xxh64(out, olen, 0);
    if (ck != slot->stored_checksum) { free(out); slot->output = NULL; slot->output_len = 0; slot->error = ZUPT_ERR_BAD_CHECKSUM; return; }

    slot->output = out;
    slot->output_len = olen;
    slot->error = ZUPT_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * WORKER THREAD ENTRY POINT
 *
 * Each worker thread has an assigned slot index (worker_id).
 * It waits for its slot to become READY, processes it, marks DONE.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    zpar_ctx_t *ctx;
    int worker_id;
} worker_arg_t;

static void *worker_entry(void *arg) {
    worker_arg_t *wa = (worker_arg_t *)arg;
    zpar_ctx_t *ctx = wa->ctx;
    int my_slot = wa->worker_id;
    free(wa);  /* Allocated by zpar_create */

    while (1) {
        zmutex_lock(&ctx->mutex);
        /* Wait until our slot is READY or shutdown */
        while (ctx->slots[my_slot].status != ZPAR_READY && !ctx->shutdown) {
            zcond_wait(&ctx->work_ready, &ctx->mutex);
        }
        if (ctx->shutdown && ctx->slots[my_slot].status != ZPAR_READY) {
            zmutex_unlock(&ctx->mutex);
            break;
        }
        zmutex_unlock(&ctx->mutex);

        /* Check if another worker already errored — skip processing */
        if (zatomic_load(&ctx->error_flag)) {
            zmutex_lock(&ctx->mutex);
            ctx->slots[my_slot].error = ZUPT_ERR_CORRUPT; /* Cancelled */
            ctx->slots[my_slot].status = ZPAR_DONE;
            zcond_broadcast(&ctx->work_done);
            zmutex_unlock(&ctx->mutex);
            continue;
        }

        /* Process the block (no lock held — this is the parallel work) */
        zpar_slot_t *slot = &ctx->slots[my_slot];
        slot->error = ZUPT_OK;
        slot->output = NULL;
        slot->output_len = 0;

        if (ctx->mode == 0) {
            worker_compress(slot, &ctx->keyring);
        } else {
            worker_decompress(slot, &ctx->keyring);
        }

        /* If we errored, set the global flag */
        if (slot->error != ZUPT_OK) {
            zatomic_store(&ctx->error_flag, (int)slot->error);
        }

        /* Mark done */
        zmutex_lock(&ctx->mutex);
        slot->status = ZPAR_DONE;
        zcond_broadcast(&ctx->work_done);
        zmutex_unlock(&ctx->mutex);
    }

    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * LIFECYCLE
 * ═══════════════════════════════════════════════════════════════════ */

zpar_ctx_t *zpar_create(int nthreads, uint32_t block_size, int mode,
                         const zupt_keyring_t *keyring) {
    if (nthreads < 1) nthreads = 1;
    /* SECURITY (defense in depth): clamp the worker/slot count here too, not
     * only at the CLI. A direct library/API caller could otherwise request an
     * arbitrary count and exhaust memory (per-slot input buffers) and thread
     * handles. The CLI already clamps -t to the same ceiling. */
    if (nthreads > ZUPT_MAX_THREADS) nthreads = ZUPT_MAX_THREADS;

    zpar_ctx_t *ctx = (zpar_ctx_t *)calloc(1, sizeof(zpar_ctx_t));
    if (!ctx) return NULL;

    ctx->nthreads = nthreads;
    ctx->nslots = nthreads;
    ctx->block_size = block_size;
    ctx->mode = mode;
    ctx->shutdown = 0;
    zatomic_store(&ctx->error_flag, 0);

    if (keyring) memcpy(&ctx->keyring, keyring, sizeof(zupt_keyring_t));
    else memset(&ctx->keyring, 0, sizeof(zupt_keyring_t));

    /* Allocate slots */
    ctx->slots = (zpar_slot_t *)calloc((size_t)nthreads, sizeof(zpar_slot_t));
    if (!ctx->slots) { free(ctx); return NULL; }

    /* Pre-allocate input buffers for each slot */
    size_t ibuf_size = (mode == 0) ? block_size : (block_size + 4096);
    for (int i = 0; i < nthreads; i++) {
        ctx->slots[i].input = (uint8_t *)malloc(ibuf_size);
        if (!ctx->slots[i].input) {
            for (int j = 0; j < i; j++) free(ctx->slots[j].input);
            free(ctx->slots); free(ctx);
            return NULL;
        }
        ctx->slots[i].status = ZPAR_EMPTY;
    }

    zmutex_init(&ctx->mutex);
    zcond_init(&ctx->work_ready);
    zcond_init(&ctx->work_done);

    /* Launch worker threads */
    ctx->threads = (zthread_t *)calloc((size_t)nthreads, sizeof(zthread_t));
    if (!ctx->threads) { zpar_destroy(ctx); return NULL; }

    ctx->threads_running = 0;
    for (int i = 0; i < nthreads; i++) {
        worker_arg_t *wa = (worker_arg_t *)malloc(sizeof(worker_arg_t));
        if (!wa) break;
        wa->ctx = ctx;
        wa->worker_id = i;
        if (zthread_create(&ctx->threads[i], worker_entry, wa) != 0) {
            free(wa);
            break;
        }
        ctx->threads_running++;
    }

    /* If no threads started, fall back gracefully (caller can check) */
    if (ctx->threads_running == 0 && nthreads > 0) {
        fprintf(stderr, "  Warning: thread creation failed, using single thread\n");
    }

    return ctx;
}

void zpar_destroy(zpar_ctx_t *ctx) {
    if (!ctx) return;

    /* Signal shutdown */
    zmutex_lock(&ctx->mutex);
    ctx->shutdown = 1;
    zcond_broadcast(&ctx->work_ready);
    zmutex_unlock(&ctx->mutex);

    /* Join all running threads */
    for (int i = 0; i < ctx->threads_running; i++) {
        zthread_join(ctx->threads[i]);
    }
    free(ctx->threads);

    /* Free slot buffers */
    if (ctx->slots) {
        for (int i = 0; i < ctx->nslots; i++) {
            free(ctx->slots[i].input);
            free(ctx->slots[i].output);
        }
        free(ctx->slots);
    }

    /* Wipe keyring copy */
    zupt_secure_wipe(&ctx->keyring, sizeof(ctx->keyring));

    zcond_destroy(&ctx->work_done);
    zcond_destroy(&ctx->work_ready);
    zmutex_destroy(&ctx->mutex);

    free(ctx);
}

/* ═══════════════════════════════════════════════════════════════════
 * SUBMIT / WAIT / RELEASE
 * ═══════════════════════════════════════════════════════════════════ */

int zpar_submit_compress(zpar_ctx_t *ctx, const uint8_t *data, size_t len,
                          uint64_t block_seq, int level, uint16_t codec_id) {
    /* Find an empty slot (round-robin, starting from block_seq mod nslots) */
    int idx = (int)(block_seq % (uint64_t)ctx->nslots);

    zmutex_lock(&ctx->mutex);
    /* Wait for slot to be empty (backpressure) */
    while (ctx->slots[idx].status != ZPAR_EMPTY && !ctx->shutdown) {
        zcond_wait(&ctx->work_done, &ctx->mutex);
    }
    if (ctx->shutdown) { zmutex_unlock(&ctx->mutex); return -1; }

    zpar_slot_t *slot = &ctx->slots[idx];
    /* Copy input data into the pre-allocated buffer */
    if (len > ctx->block_size) { zmutex_unlock(&ctx->mutex); return -1; }
    memcpy(slot->input, data, len);
    slot->input_len = len;
    slot->block_seq = block_seq;
    slot->level = level;
    slot->codec_id = codec_id;
    slot->error = ZUPT_OK;
    free(slot->output); slot->output = NULL;
    slot->output_len = 0;

    slot->status = ZPAR_READY;
    zcond_broadcast(&ctx->work_ready);
    zmutex_unlock(&ctx->mutex);

    return idx;
}

int zpar_submit_decompress(zpar_ctx_t *ctx, const uint8_t *payload, size_t plen,
                            uint64_t block_seq, uint16_t codec_id, uint16_t bflags,
                            uint64_t checksum, uint64_t uncomp_size) {
    int idx = (int)(block_seq % (uint64_t)ctx->nslots);

    zmutex_lock(&ctx->mutex);
    while (ctx->slots[idx].status != ZPAR_EMPTY && !ctx->shutdown) {
        zcond_wait(&ctx->work_done, &ctx->mutex);
    }
    if (ctx->shutdown) { zmutex_unlock(&ctx->mutex); return -1; }

    zpar_slot_t *slot = &ctx->slots[idx];
    /* For decompress, we may need more than block_size (encrypted overhead) */
    if (plen > ctx->block_size + 4096) {
        /* Reallocate if needed — rare, only for large encrypted blocks */
        uint8_t *newbuf = (uint8_t *)realloc(slot->input, plen);
        if (!newbuf) { zmutex_unlock(&ctx->mutex); return -1; }
        slot->input = newbuf;
    }
    memcpy(slot->input, payload, plen);
    slot->input_len = plen;
    slot->block_seq = block_seq;
    slot->codec_id = codec_id;
    slot->block_flags = bflags;
    slot->stored_checksum = checksum;
    slot->uncomp_size = uncomp_size;
    slot->error = ZUPT_OK;
    free(slot->output); slot->output = NULL;
    slot->output_len = 0;

    slot->status = ZPAR_READY;
    zcond_broadcast(&ctx->work_ready);
    zmutex_unlock(&ctx->mutex);

    return idx;
}

zpar_slot_t *zpar_wait_slot(zpar_ctx_t *ctx, int slot_idx) {
    if (slot_idx < 0 || slot_idx >= ctx->nslots) return NULL;

    zmutex_lock(&ctx->mutex);
    while (ctx->slots[slot_idx].status != ZPAR_DONE && !ctx->shutdown) {
        zcond_wait(&ctx->work_done, &ctx->mutex);
    }
    zmutex_unlock(&ctx->mutex);

    return &ctx->slots[slot_idx];
}

void zpar_release_slot(zpar_ctx_t *ctx, int slot_idx) {
    if (slot_idx < 0 || slot_idx >= ctx->nslots) return;

    zmutex_lock(&ctx->mutex);
    free(ctx->slots[slot_idx].output);
    ctx->slots[slot_idx].output = NULL;
    ctx->slots[slot_idx].output_len = 0;
    ctx->slots[slot_idx].status = ZPAR_EMPTY;
    zcond_broadcast(&ctx->work_done);  /* Wake submitter if it was blocked */
    zmutex_unlock(&ctx->mutex);
}

zupt_error_t zpar_check_error(zpar_ctx_t *ctx) {
    int e = zatomic_load(&ctx->error_flag);
    return (zupt_error_t)e;
}
