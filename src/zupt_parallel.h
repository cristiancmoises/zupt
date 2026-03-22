/*
 * ZUPT v0.6.0 — Parallel Compress / Decompress Pipeline
 *
 * Batch-parallel design: the main thread reads N blocks (N = thread_count),
 * workers process them in parallel (compress+encrypt or HMAC+decrypt+decompress),
 * and the main thread writes results in sequential order.
 *
 * This avoids complex lock-free queues while achieving near-linear speedup
 * on the CPU-bound compression/decompression steps. I/O remains single-threaded
 * (sequential reads/writes are optimal for both SSDs and spinning disks).
 *
 * Design tradeoffs documented inline.
 */
#ifndef ZUPT_PARALLEL_H
#define ZUPT_PARALLEL_H

#include "zupt.h"
#include "zupt_thread.h"

/* ─── Slot states ─── */
#define ZPAR_EMPTY  0   /* Available for main thread to fill */
#define ZPAR_READY  1   /* Filled by main thread, waiting for worker */
#define ZPAR_DONE   2   /* Processed by worker, waiting for main thread to consume */

/* ─── One work slot per block ─── */
typedef struct {
    /* Input (filled by main thread before setting status=READY) */
    uint8_t  *input;          /* Uncompressed block data (compress) or raw payload (decompress) */
    size_t    input_len;
    uint64_t  block_seq;      /* Nonce derivation: base_nonce XOR block_seq */
    int       level;
    uint16_t  codec_id;       /* Requested codec (compress) or actual codec (decompress) */
    uint16_t  block_flags;    /* For decompress: ZUPT_BFLAG_ENCRYPTED etc. */
    uint64_t  stored_checksum;/* For decompress: expected XXH64 */
    uint64_t  uncomp_size;    /* For decompress: expected output size */

    /* Output (filled by worker before setting status=DONE) */
    uint8_t  *output;         /* Compressed+encrypted payload (compress) or decompressed data (decompress) */
    size_t    output_len;
    uint16_t  actual_codec;   /* Actual codec used (may fall back to STORE) */
    uint16_t  out_bflags;     /* Output block flags */
    uint64_t  checksum;       /* XXH64 of uncompressed data */
    zupt_error_t error;       /* ZUPT_OK or error code */

    /* Synchronization */
    int status;               /* ZPAR_EMPTY / ZPAR_READY / ZPAR_DONE */
} zpar_slot_t;

/* ─── Parallel context ─── */
typedef struct {
    /* Configuration */
    int           nthreads;
    uint32_t      block_size;
    zupt_keyring_t keyring;   /* Copied once; workers read-only (per-block nonce derived from block_seq) */

    /* Worker threads */
    zthread_t    *threads;
    int           threads_running;

    /* Work slots: one per thread. Workers scan for their assigned slot. */
    zpar_slot_t  *slots;
    int           nslots;

    /* Synchronization */
    zmutex_t      mutex;
    zcond_t       work_ready;    /* Main → workers: new batch available */
    zcond_t       work_done;     /* Workers → main: slot completed */
    int           shutdown;      /* Set to 1 to terminate workers */
    zatomic_int   error_flag;    /* Non-zero if any worker hit an error */

    /* Mode: 0 = compress, 1 = decompress */
    int           mode;
} zpar_ctx_t;

/* ─── API ─── */

/* Create parallel context. mode: 0=compress, 1=decompress.
 * keyring may be NULL if encryption is not active.
 * Returns NULL on allocation failure. */
zpar_ctx_t *zpar_create(int nthreads, uint32_t block_size, int mode,
                         const zupt_keyring_t *keyring);

/* Destroy context: signal shutdown, join threads, free all memory.
 * Wipes keyring copy. */
void zpar_destroy(zpar_ctx_t *ctx);

/* Submit a block for compression. Finds an empty slot, copies input data,
 * sets status=READY. Blocks if no slot available (backpressure).
 * Returns the slot index, or -1 on error. */
int zpar_submit_compress(zpar_ctx_t *ctx, const uint8_t *data, size_t len,
                          uint64_t block_seq, int level, uint16_t codec_id);

/* Submit a block for decompression. */
int zpar_submit_decompress(zpar_ctx_t *ctx, const uint8_t *payload, size_t plen,
                            uint64_t block_seq, uint16_t codec_id, uint16_t bflags,
                            uint64_t checksum, uint64_t uncomp_size);

/* Wait for slot to reach DONE state. Returns the slot pointer.
 * Caller must consume the output and call zpar_release_slot() when finished. */
zpar_slot_t *zpar_wait_slot(zpar_ctx_t *ctx, int slot_idx);

/* Release a consumed slot back to EMPTY state. */
void zpar_release_slot(zpar_ctx_t *ctx, int slot_idx);

/* Check if any worker reported an error. Returns first error code. */
zupt_error_t zpar_check_error(zpar_ctx_t *ctx);

#endif /* ZUPT_PARALLEL_H */
