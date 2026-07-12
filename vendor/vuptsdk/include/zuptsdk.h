/*
 * libvuptsdk — Public C ABI for the Zupt backup compression library
 *
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Repository: https://github.com/cristiancmoises/zupt
 * Website:    https://zupt.securityops.co
 * Contact:    zupt@riseup.net
 *
 * --------------------------------------------------------------------------
 * STABILITY GUARANTEE
 * --------------------------------------------------------------------------
 * Every symbol declared in this header is part of the stable v1.0 ABI and
 * is gated behind the linker version tag ZUPTSDK_1.0. New symbols may be
 * added in minor versions (1.1, 1.2, ...) under new tags (ZUPTSDK_1.1, ...).
 * Existing symbols will never change signature within v1.x. Breaking
 * changes require a major version bump (libvuptsdk.so.2).
 *
 * No symbol prefixed with anything other than `zuptsdk_` or `ZUPTSDK_` is
 * part of this ABI. Do not link against internal `zupt_*` symbols even if
 * they appear in the static archive — they will disappear without notice.
 *
 * --------------------------------------------------------------------------
 * THREAD SAFETY
 * --------------------------------------------------------------------------
 * Every function that takes a `zuptsdk_ctx_t *` operates only on that
 * context's state and on caller-provided buffers. Concurrent calls on
 * DISTINCT contexts are safe (MT-Safe). Concurrent calls on the SAME
 * context are NOT safe (MT-Unsafe-Same-Context) unless explicitly
 * documented otherwise.
 *
 * --------------------------------------------------------------------------
 * MEMORY OWNERSHIP
 * --------------------------------------------------------------------------
 * Every function documents ownership using these conventions in the param
 * comments:
 *   [in]               caller owns, library reads only
 *   [out]              caller owns, library writes
 *   [in,out]           caller owns, library reads and writes
 *   [transfers]        ownership moves caller -> library (or library -> caller)
 *   [borrowed]         pointer valid only for the duration of the call
 *
 * Any function that returns a heap-allocated value via an output pointer
 * documents the corresponding zuptsdk_*_destroy() or zuptsdk_free() call
 * the caller must invoke. Calling free() on libc-allocated memory from a
 * different allocator is undefined; always use the documented destroyer.
 *
 * --------------------------------------------------------------------------
 * ERROR HANDLING
 * --------------------------------------------------------------------------
 * Functions return `int` where 0 == ZUPTSDK_OK and negative values are
 * `zuptsdk_error_t` codes. Use zuptsdk_strerror() for a static description
 * and zuptsdk_last_error_detail(ctx) for a thread-local detailed message
 * including filename, line number, and underlying errno where applicable.
 *
 * The library never calls abort(), exit(), or _exit(). It never writes to
 * stdout or stderr unless the caller explicitly enables logging via
 * zuptsdk_ctx_set_log_callback().
 *
 * --------------------------------------------------------------------------
 * SECURE MEMORY
 * --------------------------------------------------------------------------
 * Inputs and outputs containing secret material (passwords, raw keys,
 * decrypted plaintext keys) MUST be passed via `zuptsdk_secure_buffer_t`
 * to ensure mlock()-backed storage and explicit_bzero() on destroy.
 * Passing such material via plain `const uint8_t *` is allowed for
 * convenience but the library cannot guarantee zeroization of caller
 * memory in that case.
 */

#ifndef ZUPTSDK_H
#define ZUPTSDK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ════════════════════════════════════════════════════════════════════════
 * VERSION
 * ════════════════════════════════════════════════════════════════════════ */

#define ZUPTSDK_VERSION_MAJOR 1
#define ZUPTSDK_VERSION_MINOR 0
#define ZUPTSDK_VERSION_PATCH 0
#define ZUPTSDK_VERSION_STRING "1.0.0"

/* Compile-time version check helper (negative if header older than required) */
#define ZUPTSDK_VERSION_AT_LEAST(maj, min, pat) \
    ((ZUPTSDK_VERSION_MAJOR > (maj)) || \
     (ZUPTSDK_VERSION_MAJOR == (maj) && ZUPTSDK_VERSION_MINOR > (min)) || \
     (ZUPTSDK_VERSION_MAJOR == (maj) && ZUPTSDK_VERSION_MINOR == (min) && \
      ZUPTSDK_VERSION_PATCH >= (pat)))

/**
 * Return the runtime version string of the linked library, e.g. "1.0.0".
 * The returned pointer is to static storage and must NOT be freed.
 *
 * Use this with the compile-time ZUPTSDK_VERSION_STRING to detect mismatch
 * between header and library at runtime.
 */
const char *zuptsdk_version_string(void);

/**
 * Verify that the linked library is at least the requested version.
 * Returns 0 if compatible, ZUPTSDK_ERR_VERSION_MISMATCH otherwise.
 * Call this once at startup before any other zuptsdk_* function.
 */
int zuptsdk_version_check(int major, int minor, int patch);

/* ════════════════════════════════════════════════════════════════════════
 * ERRORS
 * ════════════════════════════════════════════════════════════════════════ */

typedef enum {
    ZUPTSDK_OK                     =   0,
    ZUPTSDK_ERR_INVALID_ARG        =  -1,  /* NULL pointer, bad size, bad enum value */
    ZUPTSDK_ERR_NO_MEMORY          =  -2,  /* malloc/calloc/realloc returned NULL */
    ZUPTSDK_ERR_IO                 =  -3,  /* read/write error; see errno detail */
    ZUPTSDK_ERR_BAD_ARCHIVE        =  -4,  /* Magic mismatch or truncated header */
    ZUPTSDK_ERR_BAD_PASSWORD       =  -5,  /* MAC verification failed */
    ZUPTSDK_ERR_BAD_KEY            =  -6,  /* PQ key file malformed or wrong type */
    ZUPTSDK_ERR_BAD_MAC            =  -7,  /* HMAC mismatch — archive corrupted or tampered */
    ZUPTSDK_ERR_BAD_VERSION        =  -8,  /* Archive format version not supported */
    ZUPTSDK_ERR_BAD_CHECKSUM       =  -9,  /* Block checksum mismatch */
    ZUPTSDK_ERR_BUFFER_TOO_SMALL   = -10,  /* Output buffer insufficient */
    ZUPTSDK_ERR_NOT_ENCRYPTED      = -11,  /* Tried to decrypt unencrypted archive */
    ZUPTSDK_ERR_PASSWORD_REQUIRED  = -12,  /* Archive needs password but none supplied */
    ZUPTSDK_ERR_PQ_KEY_REQUIRED    = -13,  /* Archive needs PQ key but none supplied */
    ZUPTSDK_ERR_UNSUPPORTED        = -14,  /* Feature not supported on this platform */
    ZUPTSDK_ERR_VERSION_MISMATCH   = -15,  /* Library older than requested */
    ZUPTSDK_ERR_PATH_TRAVERSAL     = -16,  /* "../" or absolute path in archive */
    ZUPTSDK_ERR_TOO_LARGE          = -17,  /* Decompressed size exceeds limit */
    ZUPTSDK_ERR_CRYPTO_FAIL        = -18,  /* Underlying crypto primitive failed */
    ZUPTSDK_ERR_CANCELLED          = -19,  /* Caller cancelled via progress callback */
    ZUPTSDK_ERR_INTERNAL           = -99   /* Bug in library — please report */
} zuptsdk_error_t;

/**
 * Static error description for a zuptsdk_error_t value.
 * Returned pointer is static and must not be freed. Always non-NULL.
 */
const char *zuptsdk_strerror(int err);

/**
 * Thread-local detailed error message from the most recent failed call.
 * The string includes file:line of the failure point and underlying errno
 * description where applicable. Returned pointer is to thread-local
 * storage, valid until the next failed zuptsdk_* call on this thread.
 * Returns "" if no error has been recorded on this thread.
 */
const char *zuptsdk_last_error_detail(void);

/* ════════════════════════════════════════════════════════════════════════
 * OPAQUE TYPES (forward declarations only — no struct layout exposed)
 * ════════════════════════════════════════════════════════════════════════ */

typedef struct zuptsdk_ctx          zuptsdk_ctx_t;
typedef struct zuptsdk_options      zuptsdk_options_t;
typedef struct zuptsdk_archive_info zuptsdk_archive_info_t;
typedef struct zuptsdk_secure_buf   zuptsdk_secure_buf_t;
typedef struct zuptsdk_keypair      zuptsdk_keypair_t;
typedef struct zuptsdk_pubkey       zuptsdk_pubkey_t;
typedef struct zuptsdk_privkey      zuptsdk_privkey_t;

/* ════════════════════════════════════════════════════════════════════════
 * ENUMS
 * ════════════════════════════════════════════════════════════════════════ */

typedef enum {
    ZUPTSDK_CODEC_AUTO     = 0,    /* Hardware-adaptive (VaptVupt on AVX2, LZHP otherwise) */
    ZUPTSDK_CODEC_VAPTVUPT = 1,    /* VaptVupt LZ + ANS entropy */
    ZUPTSDK_CODEC_LZHP     = 2,    /* LZ77 + Huffman + Byte Prediction */
    ZUPTSDK_CODEC_LZH      = 3,    /* LZ77 + Huffman */
    ZUPTSDK_CODEC_LZ       = 4,    /* LZ77 only */
    ZUPTSDK_CODEC_STORE    = 5     /* No compression */
} zuptsdk_codec_t;

typedef enum {
    ZUPTSDK_ENC_NONE       = 0,    /* No encryption */
    ZUPTSDK_ENC_PASSWORD   = 1,    /* PBKDF2 → AES-256-CTR + HMAC-SHA256 */
    ZUPTSDK_ENC_PQ_HYBRID  = 2     /* ML-KEM-768 + X25519 hybrid KEM */
} zuptsdk_encryption_t;

typedef enum {
    ZUPTSDK_LOG_ERROR = 0,
    ZUPTSDK_LOG_WARN  = 1,
    ZUPTSDK_LOG_INFO  = 2,
    ZUPTSDK_LOG_DEBUG = 3
} zuptsdk_log_level_t;

/* ════════════════════════════════════════════════════════════════════════
 * CALLBACKS
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Streaming read callback. Library calls this to obtain input bytes.
 * @param userdata  [in]  opaque pointer supplied at stream init
 * @param buf       [out] destination buffer
 * @param max_bytes max bytes to read into buf
 * @return Number of bytes actually read (0 == EOF, < 0 == error).
 */
typedef int64_t (*zuptsdk_read_fn)(void *userdata, uint8_t *buf, size_t max_bytes);

/**
 * Streaming write callback. Library calls this to deliver output bytes.
 * @param userdata  [in]  opaque pointer supplied at stream init
 * @param buf       [in]  data to write
 * @param bytes     number of bytes in buf
 * @return Number of bytes actually written (must equal `bytes` on success).
 */
typedef int64_t (*zuptsdk_write_fn)(void *userdata, const uint8_t *buf, size_t bytes);

/**
 * Progress callback. Library invokes periodically during long operations.
 * Return non-zero to cancel the operation; the in-flight call will then
 * return ZUPTSDK_ERR_CANCELLED.
 * @param userdata    [in] opaque pointer set via zuptsdk_ctx_set_progress_callback
 * @param processed   bytes processed so far
 * @param total       total bytes (0 if unknown)
 * @return 0 to continue, non-zero to cancel.
 */
typedef int (*zuptsdk_progress_fn)(void *userdata, uint64_t processed, uint64_t total);

/**
 * Log callback. Receives diagnostic messages from the library.
 * Set via zuptsdk_ctx_set_log_callback(). NULL means no logging (default).
 * The string is null-terminated and valid only for the duration of the call.
 */
typedef void (*zuptsdk_log_fn)(void *userdata, zuptsdk_log_level_t level, const char *msg);

/**
 * Custom allocator hooks. Set globally via zuptsdk_set_allocator().
 * If any function is NULL, libc malloc/free/realloc is used.
 * realloc_fn must accept (NULL, n) as malloc(n) and (p, 0) as free(p).
 */
typedef struct {
    void *(*malloc_fn)(void *userdata, size_t size);
    void  (*free_fn)(void *userdata, void *ptr);
    void *(*realloc_fn)(void *userdata, void *ptr, size_t size);
    void  *userdata;
} zuptsdk_allocator_t;

/* ════════════════════════════════════════════════════════════════════════
 * GLOBAL CONFIG
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Install a custom allocator. Must be called before any other zuptsdk_*
 * function. Calling after contexts have been created is undefined.
 * Pass NULL to revert to libc allocator (only valid before first use).
 *
 * @param alloc [in,borrowed] allocator hooks; copied internally
 * @return ZUPTSDK_OK or ZUPTSDK_ERR_INVALID_ARG
 */
int zuptsdk_set_allocator(const zuptsdk_allocator_t *alloc);

/* ════════════════════════════════════════════════════════════════════════
 * CONTEXT
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Create a new SDK context. Each context holds its own thread pool,
 * progress callback, log callback, and error state. Contexts are
 * cheap to create — a few KB plus the configured thread count.
 *
 * @param ctx_out [out,transfers] pointer to receive new context
 * @return ZUPTSDK_OK on success, ZUPTSDK_ERR_NO_MEMORY on alloc failure.
 *         On error, *ctx_out is set to NULL.
 */
int zuptsdk_ctx_create(zuptsdk_ctx_t **ctx_out);

/**
 * Destroy a context. Frees all owned resources including thread pool.
 * Safe to call with NULL. After this call, the pointer is invalid.
 */
void zuptsdk_ctx_destroy(zuptsdk_ctx_t *ctx);

/**
 * Set worker thread count. 0 == auto (one per CPU). Default is auto.
 * Returns ZUPTSDK_ERR_INVALID_ARG if ctx is NULL or threads > 256.
 */
int zuptsdk_ctx_set_threads(zuptsdk_ctx_t *ctx, int threads);

/**
 * Set progress callback for long-running operations on this context.
 * Pass NULL fn to clear. userdata is opaque to the library.
 */
int zuptsdk_ctx_set_progress_callback(zuptsdk_ctx_t *ctx,
                                      zuptsdk_progress_fn fn,
                                      void *userdata);

/**
 * Set log callback for diagnostic messages on this context.
 * Pass NULL fn to disable logging (default).
 */
int zuptsdk_ctx_set_log_callback(zuptsdk_ctx_t *ctx,
                                 zuptsdk_log_fn fn,
                                 zuptsdk_log_level_t min_level,
                                 void *userdata);

/* ════════════════════════════════════════════════════════════════════════
 * OPTIONS
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Create a default-initialized options bag for compress/encrypt operations.
 * Defaults: codec=AUTO, level=7, no encryption, no dedup, no solid mode.
 */
int zuptsdk_options_create(zuptsdk_options_t **opts_out);
void zuptsdk_options_destroy(zuptsdk_options_t *opts);

int zuptsdk_options_set_codec(zuptsdk_options_t *opts, zuptsdk_codec_t codec);
int zuptsdk_options_set_level(zuptsdk_options_t *opts, int level /* 1..9 */);
int zuptsdk_options_set_dedup(zuptsdk_options_t *opts, int enabled);
int zuptsdk_options_set_solid(zuptsdk_options_t *opts, int enabled);
int zuptsdk_options_set_block_size(zuptsdk_options_t *opts, size_t bytes);

/**
 * Maximum decompressed output size. Decompression aborts with
 * ZUPTSDK_ERR_TOO_LARGE if exceeded. 0 == unlimited (NOT recommended
 * for untrusted input — zip-bomb attack vector). Default: 16 GiB.
 */
int zuptsdk_options_set_max_decompressed(zuptsdk_options_t *opts,
                                         uint64_t max_bytes);

/* ════════════════════════════════════════════════════════════════════════
 * SECURE BUFFERS (for passwords and key material)
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Allocate a secure buffer: backing memory is mlock()ed (locked into RAM,
 * never swapped to disk) and explicit_bzero()ed on destroy.
 *
 * @param size      requested size in bytes (1..65536)
 * @param buf_out   [out,transfers] receives buffer handle
 * @return ZUPTSDK_OK on success.
 */
int zuptsdk_secure_buf_create(size_t size, zuptsdk_secure_buf_t **buf_out);

/**
 * Destroy a secure buffer. Memory is zeroed and unlocked before free.
 * Safe to call with NULL.
 */
void zuptsdk_secure_buf_destroy(zuptsdk_secure_buf_t *buf);

/**
 * Get raw pointer to the secure buffer's storage. Pointer is valid until
 * zuptsdk_secure_buf_destroy() is called. Caller may read or write up to
 * the buffer's size.
 *
 * @param buf      [in]
 * @param data_out [out,borrowed] receives pointer to storage
 * @param size_out [out] receives buffer size
 */
int zuptsdk_secure_buf_get(zuptsdk_secure_buf_t *buf,
                           uint8_t **data_out, size_t *size_out);

/**
 * Convenience: copy data into a new secure buffer.
 * Useful when migrating an existing plain buffer to secure storage.
 */
int zuptsdk_secure_buf_from_data(const uint8_t *data, size_t size,
                                 zuptsdk_secure_buf_t **buf_out);

/* ════════════════════════════════════════════════════════════════════════
 * KEYS (PQ hybrid: ML-KEM-768 + X25519)
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Generate a fresh hybrid keypair. Uses the system CSPRNG.
 *
 * @param ctx     [in]
 * @param kp_out  [out,transfers] receives new keypair
 * @return ZUPTSDK_OK on success, ZUPTSDK_ERR_CRYPTO_FAIL on RNG failure.
 */
int zuptsdk_keypair_generate(zuptsdk_ctx_t *ctx, zuptsdk_keypair_t **kp_out);

void zuptsdk_keypair_destroy(zuptsdk_keypair_t *kp);

/**
 * Save private key to a file. The file is written with mode 0600 on POSIX.
 * Recommended extension: ".key".
 */
int zuptsdk_keypair_save_private(const zuptsdk_keypair_t *kp, const char *path);

/**
 * Save public key to a file. World-readable.
 * Recommended extension: ".pub" or "_public.key".
 */
int zuptsdk_keypair_save_public(const zuptsdk_keypair_t *kp, const char *path);

/**
 * Load a private key from a file.
 * @param path     [in]
 * @param key_out  [out,transfers]
 */
int zuptsdk_privkey_load(const char *path, zuptsdk_privkey_t **key_out);
void zuptsdk_privkey_destroy(zuptsdk_privkey_t *key);

/**
 * Load a public key from a file.
 */
int zuptsdk_pubkey_load(const char *path, zuptsdk_pubkey_t **key_out);
void zuptsdk_pubkey_destroy(zuptsdk_pubkey_t *key);

/**
 * Derive public key from private key (no I/O).
 */
int zuptsdk_privkey_get_public(const zuptsdk_privkey_t *priv,
                               zuptsdk_pubkey_t **pub_out);

/* ════════════════════════════════════════════════════════════════════════
 * COMPRESS / DECOMPRESS — buffer mode (for small archives)
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Compress an in-memory file list into a single archive buffer.
 *
 * @param ctx          [in]
 * @param opts         [in,borrowed] compression and encryption options
 * @param file_paths   [in] array of filesystem paths to add
 * @param file_count   number of paths in file_paths
 * @param password     [in,nullable] password as a secure buffer; NULL for no pw
 * @param recipient_pk [in,nullable] PQ public key for encryption; NULL for no PQ
 * @param archive_out  [out,transfers] receives malloc'd archive bytes;
 *                     caller must free with zuptsdk_free()
 * @param archive_sz   [out] size of returned archive
 * @return ZUPTSDK_OK on success.
 */
int zuptsdk_compress_files(zuptsdk_ctx_t *ctx,
                           const zuptsdk_options_t *opts,
                           const char *const *file_paths,
                           size_t file_count,
                           zuptsdk_secure_buf_t *password,
                           const zuptsdk_pubkey_t *recipient_pk,
                           uint8_t **archive_out,
                           size_t *archive_sz);

/**
 * Compress a single in-memory data buffer. Useful for SDK consumers that
 * have data in memory and want a self-contained archive.
 *
 * @param logical_name [in] name to record inside the archive (e.g. "data.bin")
 */
int zuptsdk_compress_buffer(zuptsdk_ctx_t *ctx,
                            const zuptsdk_options_t *opts,
                            const char *logical_name,
                            const uint8_t *data, size_t data_sz,
                            zuptsdk_secure_buf_t *password,
                            const zuptsdk_pubkey_t *recipient_pk,
                            uint8_t **archive_out,
                            size_t *archive_sz);

/**
 * Extract an archive into a directory.
 *
 * @param dest_dir     [in] target directory; created if missing
 * @param password     [in,nullable]
 * @param recipient_sk [in,nullable] PQ private key
 */
int zuptsdk_extract_to_dir(zuptsdk_ctx_t *ctx,
                           const uint8_t *archive, size_t archive_sz,
                           const char *dest_dir,
                           zuptsdk_secure_buf_t *password,
                           const zuptsdk_privkey_t *recipient_sk);

/**
 * Extract a single-file archive (one created with zuptsdk_compress_buffer)
 * back into a memory buffer.
 *
 * @param data_out [out,transfers] caller frees with zuptsdk_free()
 * @param data_sz  [out]
 */
int zuptsdk_extract_buffer(zuptsdk_ctx_t *ctx,
                           const uint8_t *archive, size_t archive_sz,
                           zuptsdk_secure_buf_t *password,
                           const zuptsdk_privkey_t *recipient_sk,
                           uint8_t **data_out, size_t *data_sz);

/* ════════════════════════════════════════════════════════════════════════
 * COMPRESS / DECOMPRESS — streaming mode (for large archives)
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Compress from a read callback to a write callback. Streaming version
 * with no archive size limit — suitable for piping to network sockets,
 * encrypted volumes, or any backend with a write_fn.
 *
 * @param input        [in] read callback supplying source bytes
 * @param input_ud     [in] userdata passed to read callback
 * @param input_name   [in] logical filename to record in archive
 * @param input_total  total bytes to read; 0 if unknown
 * @param output       [in] write callback receiving archive bytes
 * @param output_ud    [in] userdata passed to write callback
 */
int zuptsdk_compress_stream(zuptsdk_ctx_t *ctx,
                            const zuptsdk_options_t *opts,
                            zuptsdk_read_fn input, void *input_ud,
                            const char *input_name, uint64_t input_total,
                            zuptsdk_write_fn output, void *output_ud,
                            zuptsdk_secure_buf_t *password,
                            const zuptsdk_pubkey_t *recipient_pk);

/**
 * Decompress an archive read from a callback, writing extracted single-file
 * content to a write callback.
 */
int zuptsdk_decompress_stream(zuptsdk_ctx_t *ctx,
                              zuptsdk_read_fn input, void *input_ud,
                              zuptsdk_write_fn output, void *output_ud,
                              zuptsdk_secure_buf_t *password,
                              const zuptsdk_privkey_t *recipient_sk);

/* ════════════════════════════════════════════════════════════════════════
 * VERIFY / INFO
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Verify all block checksums and (if encrypted) HMAC of an archive.
 * No data is written to disk. Returns ZUPTSDK_OK if every block validates.
 */
int zuptsdk_verify(zuptsdk_ctx_t *ctx,
                   const uint8_t *archive, size_t archive_sz,
                   zuptsdk_secure_buf_t *password,
                   const zuptsdk_privkey_t *recipient_sk);

/**
 * Read archive metadata without password or key. Returns header info only;
 * does not decrypt block contents.
 *
 * @param info_out [out,transfers] receives info object;
 *                 caller must zuptsdk_archive_info_destroy()
 */
int zuptsdk_archive_info_read(zuptsdk_ctx_t *ctx,
                              const uint8_t *archive, size_t archive_sz,
                              zuptsdk_archive_info_t **info_out);

void zuptsdk_archive_info_destroy(zuptsdk_archive_info_t *info);

/* Getters — opaque struct, all fields accessed via these functions. */
int         zuptsdk_archive_info_format_major(const zuptsdk_archive_info_t *info);
int         zuptsdk_archive_info_format_minor(const zuptsdk_archive_info_t *info);
const char *zuptsdk_archive_info_uuid(const zuptsdk_archive_info_t *info);
int64_t     zuptsdk_archive_info_created_unix(const zuptsdk_archive_info_t *info);
uint64_t    zuptsdk_archive_info_size(const zuptsdk_archive_info_t *info);
uint32_t    zuptsdk_archive_info_block_count(const zuptsdk_archive_info_t *info);
int         zuptsdk_archive_info_is_encrypted(const zuptsdk_archive_info_t *info);
int         zuptsdk_archive_info_is_pq_hybrid(const zuptsdk_archive_info_t *info);
int         zuptsdk_archive_info_is_solid(const zuptsdk_archive_info_t *info);
int         zuptsdk_archive_info_is_dedup(const zuptsdk_archive_info_t *info);
int         zuptsdk_archive_info_is_disk_image(const zuptsdk_archive_info_t *info);

/* ════════════════════════════════════════════════════════════════════════
 * DISK BACKUP / RESTORE
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Backup a block device or disk image file to an archive.
 * REQUIRES root/admin privileges to read raw block devices on most OSes.
 */
int zuptsdk_disk_backup(zuptsdk_ctx_t *ctx,
                        const zuptsdk_options_t *opts,
                        const char *source_device_or_image,
                        const char *output_archive_path,
                        zuptsdk_secure_buf_t *password,
                        const zuptsdk_pubkey_t *recipient_pk);

/**
 * Restore a disk backup archive to a block device or image file.
 * DESTRUCTIVE: target is overwritten without confirmation.
 */
int zuptsdk_disk_restore(zuptsdk_ctx_t *ctx,
                         const char *archive_path,
                         const char *target_device_or_image,
                         zuptsdk_secure_buf_t *password,
                         const zuptsdk_privkey_t *recipient_sk);

/* ════════════════════════════════════════════════════════════════════════
 * MISC
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Free memory returned by the library via [transfers] output pointers.
 * Safe to call with NULL.
 *
 * Always use this — never free() — for SDK-allocated memory, since the
 * library may have been built with a custom allocator.
 */
void zuptsdk_free(void *ptr);

/**
 * Best-effort secure zero of a buffer. Resistant to dead-store elimination
 * by the optimizer. Use for caller-managed sensitive memory.
 */
void zuptsdk_secure_zero(void *buf, size_t bytes);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZUPTSDK_H */
