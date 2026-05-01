/*
 * libzuptsdk implementation — wraps zupt's internal API
 *
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _DEFAULT_SOURCE 1

#include "zuptsdk.h"
#include "zupt.h"
#include "zupt_keccak.h"
#include "zupt_mlkem.h"
#include "zupt_x25519.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
  #include <windows.h>
  #include <io.h>
  #define ZSDK_THREAD_LOCAL __declspec(thread)
#else
  #include <fcntl.h>
  #include <sys/mman.h>
  #include <sys/stat.h>
  #include <unistd.h>
  #define ZSDK_THREAD_LOCAL __thread
#endif

/* ════════════════════════════════════════════════════════════════════════
 * Internal: allocator routing
 * ════════════════════════════════════════════════════════════════════════ */

static zuptsdk_allocator_t g_alloc = { NULL, NULL, NULL, NULL };

static void *zsdk_malloc(size_t n) {
    if (g_alloc.malloc_fn) return g_alloc.malloc_fn(g_alloc.userdata, n);
    return malloc(n);
}

static void zsdk_free_internal(void *p) {
    if (!p) return;
    if (g_alloc.free_fn) { g_alloc.free_fn(g_alloc.userdata, p); return; }
    free(p);
}

static void *zsdk_calloc(size_t count, size_t size) {
    if (count && size > SIZE_MAX / count) { errno = ENOMEM; return NULL; }
    size_t total = count * size;
    void *p = zsdk_malloc(total);
    if (p) memset(p, 0, total);
    return p;
}

static char *zsdk_strdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char *)zsdk_malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

/* ════════════════════════════════════════════════════════════════════════
 * Internal: thread-local error detail
 * ════════════════════════════════════════════════════════════════════════ */

static ZSDK_THREAD_LOCAL char g_err_detail[512] = {0};

static int zsdk_set_error(int code, const char *file, int line, const char *fmt, ...) {
    char msg[400] = {0};
    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
    }
    if (file) {
        const char *base = strrchr(file, '/');
        base = base ? base + 1 : file;
        snprintf(g_err_detail, sizeof(g_err_detail),
                 "[%s] %s:%d: %s%s%s",
                 zuptsdk_strerror(code), base, line, msg,
                 errno ? " (errno: " : "",
                 errno ? strerror(errno) : "");
        if (errno) strncat(g_err_detail, ")",
                           sizeof(g_err_detail) - strlen(g_err_detail) - 1);
    } else {
        snprintf(g_err_detail, sizeof(g_err_detail),
                 "[%s] %s", zuptsdk_strerror(code), msg);
    }
    return code;
}

#define ZSDK_FAIL(code, ...) zsdk_set_error((code), __FILE__, __LINE__, __VA_ARGS__)
#define ZSDK_OK(...) (g_err_detail[0] = 0, ZUPTSDK_OK)

/* ════════════════════════════════════════════════════════════════════════
 * Internal: error mapping zupt_error_t -> zuptsdk_error_t
 * ════════════════════════════════════════════════════════════════════════ */

static int zsdk_map_zupt_error(zupt_error_t e) {
    switch (e) {
        case ZUPT_OK:                return ZUPTSDK_OK;
        case ZUPT_ERR_IO:            return ZUPTSDK_ERR_IO;
        case ZUPT_ERR_CORRUPT:       return ZUPTSDK_ERR_BAD_ARCHIVE;
        case ZUPT_ERR_BAD_MAGIC:     return ZUPTSDK_ERR_BAD_ARCHIVE;
        case ZUPT_ERR_BAD_VERSION:   return ZUPTSDK_ERR_BAD_VERSION;
        case ZUPT_ERR_BAD_CHECKSUM:  return ZUPTSDK_ERR_BAD_CHECKSUM;
        case ZUPT_ERR_NOMEM:         return ZUPTSDK_ERR_NO_MEMORY;
        case ZUPT_ERR_OVERFLOW:      return ZUPTSDK_ERR_TOO_LARGE;
        case ZUPT_ERR_INVALID:       return ZUPTSDK_ERR_INVALID_ARG;
        case ZUPT_ERR_NOT_FOUND:     return ZUPTSDK_ERR_IO;
        case ZUPT_ERR_UNSUPPORTED:   return ZUPTSDK_ERR_UNSUPPORTED;
        case ZUPT_ERR_AUTH_FAIL:     return ZUPTSDK_ERR_BAD_PASSWORD;
        default:                     return ZUPTSDK_ERR_INTERNAL;
    }
}

/* ════════════════════════════════════════════════════════════════════════
 * Public: version
 * ════════════════════════════════════════════════════════════════════════ */

const char *zuptsdk_version_string(void) {
    return ZUPTSDK_VERSION_STRING;
}

int zuptsdk_version_check(int major, int minor, int patch) {
    if (major  >  ZUPTSDK_VERSION_MAJOR) return ZSDK_FAIL(ZUPTSDK_ERR_VERSION_MISMATCH,
        "library is %d.%d.%d, caller required %d.%d.%d",
        ZUPTSDK_VERSION_MAJOR, ZUPTSDK_VERSION_MINOR, ZUPTSDK_VERSION_PATCH,
        major, minor, patch);
    if (major  == ZUPTSDK_VERSION_MAJOR && minor  > ZUPTSDK_VERSION_MINOR)
        return ZSDK_FAIL(ZUPTSDK_ERR_VERSION_MISMATCH, "minor version too low");
    if (major  == ZUPTSDK_VERSION_MAJOR && minor == ZUPTSDK_VERSION_MINOR &&
        patch  >  ZUPTSDK_VERSION_PATCH)
        return ZSDK_FAIL(ZUPTSDK_ERR_VERSION_MISMATCH, "patch version too low");
    return ZUPTSDK_OK;
}

/* Helper to copy a path into options' fixed keyfile buffer */
static int zsdk_apply_pubkey(zupt_options_t *zopts, const zuptsdk_pubkey_t *pk);
static int zsdk_apply_privkey(zupt_options_t *zopts, const zuptsdk_privkey_t *sk);

/* ════════════════════════════════════════════════════════════════════════
 * Forward struct definitions (must come before helper functions)
 * ════════════════════════════════════════════════════════════════════════ */

struct zuptsdk_pubkey  { char *path; };
struct zuptsdk_privkey { char *path; };

struct zuptsdk_keypair {
    char *priv_path;   /* persistent path; library generated key files */
    char *pub_path;
};

/* ════════════════════════════════════════════════════════════════════════
 * Public: errors
 * ════════════════════════════════════════════════════════════════════════ */

const char *zuptsdk_strerror(int err) {
    switch (err) {
        case ZUPTSDK_OK:                    return "Success";
        case ZUPTSDK_ERR_INVALID_ARG:       return "Invalid argument";
        case ZUPTSDK_ERR_NO_MEMORY:         return "Out of memory";
        case ZUPTSDK_ERR_IO:                return "I/O error";
        case ZUPTSDK_ERR_BAD_ARCHIVE:       return "Malformed archive";
        case ZUPTSDK_ERR_BAD_PASSWORD:      return "Wrong password";
        case ZUPTSDK_ERR_BAD_KEY:           return "Invalid key file";
        case ZUPTSDK_ERR_BAD_MAC:           return "MAC verification failed (corrupted or tampered)";
        case ZUPTSDK_ERR_BAD_VERSION:       return "Unsupported archive format version";
        case ZUPTSDK_ERR_BAD_CHECKSUM:      return "Block checksum mismatch";
        case ZUPTSDK_ERR_BUFFER_TOO_SMALL:  return "Output buffer too small";
        case ZUPTSDK_ERR_NOT_ENCRYPTED:     return "Archive is not encrypted";
        case ZUPTSDK_ERR_PASSWORD_REQUIRED: return "Password required";
        case ZUPTSDK_ERR_PQ_KEY_REQUIRED:   return "PQ private key required";
        case ZUPTSDK_ERR_UNSUPPORTED:       return "Feature not supported on this platform";
        case ZUPTSDK_ERR_VERSION_MISMATCH:  return "Library version too old";
        case ZUPTSDK_ERR_PATH_TRAVERSAL:    return "Path traversal attempt blocked";
        case ZUPTSDK_ERR_TOO_LARGE:         return "Decompressed size exceeds limit";
        case ZUPTSDK_ERR_CRYPTO_FAIL:       return "Cryptographic operation failed";
        case ZUPTSDK_ERR_CANCELLED:         return "Operation cancelled by callback";
        case ZUPTSDK_ERR_INTERNAL:          return "Internal library error (please report)";
        default:                            return "Unknown error";
    }
}

const char *zuptsdk_last_error_detail(void) {
    return g_err_detail;
}

/* ════════════════════════════════════════════════════════════════════════
 * Public: allocator
 * ════════════════════════════════════════════════════════════════════════ */

int zuptsdk_set_allocator(const zuptsdk_allocator_t *alloc) {
    if (!alloc) {
        memset(&g_alloc, 0, sizeof(g_alloc));
        return ZUPTSDK_OK;
    }
    if (!alloc->malloc_fn || !alloc->free_fn || !alloc->realloc_fn)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "all allocator hooks required");
    g_alloc = *alloc;
    return ZUPTSDK_OK;
}

void zuptsdk_free(void *ptr) { zsdk_free_internal(ptr); }

void zuptsdk_secure_zero(void *buf, size_t bytes) {
    if (!buf || !bytes) return;
#if defined(__STDC_LIB_EXT1__) || defined(_WIN32)
    #ifdef _WIN32
    SecureZeroMemory(buf, bytes);
    #else
    memset_s(buf, bytes, 0, bytes);
    #endif
#elif defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
    explicit_bzero(buf, bytes);
#else
    /* Fallback: volatile pointer prevents dead-store elimination */
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (bytes--) *p++ = 0;
#endif
}

/* ════════════════════════════════════════════════════════════════════════
 * Internal context structure
 * ════════════════════════════════════════════════════════════════════════ */

struct zuptsdk_ctx {
    int                  threads;       /* 0 = auto */
    zuptsdk_progress_fn  progress_fn;
    void                *progress_ud;
    zuptsdk_log_fn       log_fn;
    zuptsdk_log_level_t  log_level;
    void                *log_ud;
};

int zuptsdk_ctx_create(zuptsdk_ctx_t **ctx_out) {
    if (!ctx_out) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "ctx_out is NULL");
    zuptsdk_ctx_t *c = (zuptsdk_ctx_t *)zsdk_calloc(1, sizeof(*c));
    if (!c) return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "ctx_create");
    c->threads = 0; /* auto */
    c->log_level = ZUPTSDK_LOG_ERROR;
    *ctx_out = c;
    return ZUPTSDK_OK;
}

void zuptsdk_ctx_destroy(zuptsdk_ctx_t *ctx) {
    if (!ctx) return;
    zuptsdk_secure_zero(ctx, sizeof(*ctx));
    zsdk_free_internal(ctx);
}

int zuptsdk_ctx_set_threads(zuptsdk_ctx_t *ctx, int threads) {
    if (!ctx)               return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "ctx is NULL");
    if (threads < 0 || threads > 256)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "threads must be 0..256");
    ctx->threads = threads;
    return ZUPTSDK_OK;
}

int zuptsdk_ctx_set_progress_callback(zuptsdk_ctx_t *ctx,
                                      zuptsdk_progress_fn fn, void *userdata) {
    if (!ctx) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "ctx is NULL");
    ctx->progress_fn = fn;
    ctx->progress_ud = userdata;
    return ZUPTSDK_OK;
}

int zuptsdk_ctx_set_log_callback(zuptsdk_ctx_t *ctx, zuptsdk_log_fn fn,
                                 zuptsdk_log_level_t min_level, void *userdata) {
    if (!ctx) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "ctx is NULL");
    ctx->log_fn = fn;
    ctx->log_level = min_level;
    ctx->log_ud = userdata;
    return ZUPTSDK_OK;
}

/* ════════════════════════════════════════════════════════════════════════
 * Internal options structure
 * ════════════════════════════════════════════════════════════════════════ */

struct zuptsdk_options {
    zuptsdk_codec_t codec;
    int             level;          /* 1..9 */
    int             dedup;
    int             solid;
    size_t          block_size;     /* 0 = default */
    uint64_t        max_decompressed;
};

int zuptsdk_options_create(zuptsdk_options_t **opts_out) {
    if (!opts_out) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "opts_out is NULL");
    zuptsdk_options_t *o = (zuptsdk_options_t *)zsdk_calloc(1, sizeof(*o));
    if (!o) return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "options_create");
    o->codec = ZUPTSDK_CODEC_AUTO;
    o->level = 7;
    o->max_decompressed = 16ull * 1024 * 1024 * 1024; /* 16 GiB default */
    *opts_out = o;
    return ZUPTSDK_OK;
}

void zuptsdk_options_destroy(zuptsdk_options_t *opts) {
    if (!opts) return;
    zsdk_free_internal(opts);
}

int zuptsdk_options_set_codec(zuptsdk_options_t *opts, zuptsdk_codec_t codec) {
    if (!opts) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "opts is NULL");
    if (codec < ZUPTSDK_CODEC_AUTO || codec > ZUPTSDK_CODEC_STORE)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "bad codec value %d", (int)codec);
    opts->codec = codec;
    return ZUPTSDK_OK;
}

int zuptsdk_options_set_level(zuptsdk_options_t *opts, int level) {
    if (!opts) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "opts is NULL");
    if (level < 1 || level > 9)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "level must be 1..9");
    opts->level = level;
    return ZUPTSDK_OK;
}

int zuptsdk_options_set_dedup(zuptsdk_options_t *opts, int enabled) {
    if (!opts) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "opts is NULL");
    opts->dedup = enabled ? 1 : 0;
    return ZUPTSDK_OK;
}

int zuptsdk_options_set_solid(zuptsdk_options_t *opts, int enabled) {
    if (!opts) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "opts is NULL");
    opts->solid = enabled ? 1 : 0;
    return ZUPTSDK_OK;
}

int zuptsdk_options_set_block_size(zuptsdk_options_t *opts, size_t bytes) {
    if (!opts) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "opts is NULL");
    if (bytes && (bytes < ZUPT_MIN_BLOCK_SZ || bytes > ZUPT_MAX_BLOCK_SZ))
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG,
                         "block_size must be 0 or %u..%u",
                         (unsigned)ZUPT_MIN_BLOCK_SZ, (unsigned)ZUPT_MAX_BLOCK_SZ);
    opts->block_size = bytes;
    return ZUPTSDK_OK;
}

int zuptsdk_options_set_max_decompressed(zuptsdk_options_t *opts, uint64_t max_bytes) {
    if (!opts) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "opts is NULL");
    opts->max_decompressed = max_bytes;
    return ZUPTSDK_OK;
}

/* ════════════════════════════════════════════════════════════════════════
 * Secure buffers (mlock + zero on destroy)
 * ════════════════════════════════════════════════════════════════════════ */

struct zuptsdk_secure_buf {
    uint8_t *data;
    size_t   size;
    int      locked;   /* 1 if mlock() succeeded */
};

int zuptsdk_secure_buf_create(size_t size, zuptsdk_secure_buf_t **buf_out) {
    if (!buf_out)             return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "buf_out is NULL");
    if (size < 1 || size > 65536)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "size must be 1..65536");

    zuptsdk_secure_buf_t *b = (zuptsdk_secure_buf_t *)zsdk_calloc(1, sizeof(*b));
    if (!b) return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "secure_buf alloc");

    b->data = (uint8_t *)zsdk_calloc(1, size);
    if (!b->data) {
        zsdk_free_internal(b);
        return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "secure_buf data alloc");
    }
    b->size = size;
    b->locked = (zupt_mlock_keys(b->data, size) == 0) ? 1 : 0;
    /* mlock failure is non-fatal — we still wipe on destroy */
    *buf_out = b;
    return ZUPTSDK_OK;
}

void zuptsdk_secure_buf_destroy(zuptsdk_secure_buf_t *buf) {
    if (!buf) return;
    if (buf->data) {
        zuptsdk_secure_zero(buf->data, buf->size);
        if (buf->locked) zupt_munlock_keys(buf->data, buf->size);
        zsdk_free_internal(buf->data);
    }
    zuptsdk_secure_zero(buf, sizeof(*buf));
    zsdk_free_internal(buf);
}

int zuptsdk_secure_buf_get(zuptsdk_secure_buf_t *buf,
                           uint8_t **data_out, size_t *size_out) {
    if (!buf || !data_out || !size_out)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    *data_out = buf->data;
    *size_out = buf->size;
    return ZUPTSDK_OK;
}

int zuptsdk_secure_buf_from_data(const uint8_t *data, size_t size,
                                 zuptsdk_secure_buf_t **buf_out) {
    if (!data || !buf_out)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    int rc = zuptsdk_secure_buf_create(size, buf_out);
    if (rc != ZUPTSDK_OK) return rc;
    memcpy((*buf_out)->data, data, size);
    return ZUPTSDK_OK;
}

/* ════════════════════════════════════════════════════════════════════════
 * Internal: convert SDK options -> zupt_options_t
 * ════════════════════════════════════════════════════════════════════════ */

static uint16_t zsdk_codec_map(zuptsdk_codec_t c) {
    switch (c) {
        case ZUPTSDK_CODEC_AUTO:     return ZUPT_CODEC_AUTO;
        case ZUPTSDK_CODEC_VAPTVUPT: return ZUPT_CODEC_VAPTVUPT;
        case ZUPTSDK_CODEC_LZHP:     return ZUPT_CODEC_ZUPT_LZHP;
        case ZUPTSDK_CODEC_LZH:      return ZUPT_CODEC_ZUPT_LZH;
        case ZUPTSDK_CODEC_LZ:       return ZUPT_CODEC_ZUPT_LZ;
        case ZUPTSDK_CODEC_STORE:    return ZUPT_CODEC_STORE;
        default:                     return ZUPT_CODEC_AUTO;
    }
}

static void zsdk_apply_options(zupt_options_t *zopts,
                               const zuptsdk_options_t *sdk_opts,
                               const zuptsdk_ctx_t *ctx) {
    zupt_default_options(zopts);
    if (sdk_opts) {
        zopts->codec_id   = zsdk_codec_map(sdk_opts->codec);
        zopts->level      = sdk_opts->level;
        zopts->dedup      = sdk_opts->dedup;
        zopts->solid      = sdk_opts->solid;
        if (sdk_opts->block_size)
            zopts->block_size = (uint32_t)sdk_opts->block_size;
    }
    if (ctx && ctx->threads > 0) zopts->threads = ctx->threads;

    /* Resolve AUTO codec at call site (mirrors main.c behavior) */
    if (zopts->codec_id == ZUPT_CODEC_AUTO)
        zopts->codec_id = zupt_resolve_auto_codec();
}

/* Copy a password from secure buffer into the options' fixed-size field.
 * Returns 0 on success, ZUPTSDK_ERR_* on failure. */
static int zsdk_apply_password(zupt_options_t *zopts, zuptsdk_secure_buf_t *pw) {
    if (!pw || pw->size == 0) return ZUPTSDK_OK;
    if (pw->size >= sizeof(zopts->password))
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG,
                         "password too long (max %zu bytes)",
                         sizeof(zopts->password) - 1);
    /* Verify no embedded NUL (would silently truncate) */
    if (memchr(pw->data, 0, pw->size))
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "password contains NUL byte");

    memcpy(zopts->password, pw->data, pw->size);
    zopts->password[pw->size] = 0;
    zopts->encrypt = 1;
    return ZUPTSDK_OK;
}

static int zsdk_apply_pubkey(zupt_options_t *zopts, const zuptsdk_pubkey_t *pk) {
    if (!pk) return ZUPTSDK_OK;
    if (!pk->path || strlen(pk->path) >= sizeof(zopts->keyfile))
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "keyfile path too long");
    strncpy(zopts->keyfile, pk->path, sizeof(zopts->keyfile) - 1);
    zopts->keyfile[sizeof(zopts->keyfile) - 1] = 0;
    zopts->pq_mode = 1;
    zopts->encrypt = 1;
    return ZUPTSDK_OK;
}

static int zsdk_apply_privkey(zupt_options_t *zopts, const zuptsdk_privkey_t *sk) {
    if (!sk) return ZUPTSDK_OK;
    if (!sk->path || strlen(sk->path) >= sizeof(zopts->keyfile))
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "keyfile path too long");
    strncpy(zopts->keyfile, sk->path, sizeof(zopts->keyfile) - 1);
    zopts->keyfile[sizeof(zopts->keyfile) - 1] = 0;
    zopts->pq_mode = 1;
    return ZUPTSDK_OK;
}

/* Securely wipe password from options after use */
static void zsdk_wipe_options_secrets(zupt_options_t *zopts) {
    zuptsdk_secure_zero(zopts->password, sizeof(zopts->password));
    /* Don't wipe keyfile path — not secret */
}

/* ════════════════════════════════════════════════════════════════════════
 * Keys
 * ════════════════════════════════════════════════════════════════════════ */

static int zsdk_tmp_path(char *out, size_t cap, const char *prefix) {
#ifdef _WIN32
    char tmpdir[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpdir);
    snprintf(out, cap, "%s%s_%lx_%lx", tmpdir, prefix,
             (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
#else
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    uint8_t r[8];
    zupt_random_bytes(r, 8);
    snprintf(out, cap, "%s/%s_%d_%02x%02x%02x%02x%02x%02x%02x%02x",
             tmpdir, prefix, (int)getpid(),
             r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
#endif
    return 0;
}

int zuptsdk_keypair_generate(zuptsdk_ctx_t *ctx, zuptsdk_keypair_t **kp_out) {
    (void)ctx;
    if (!kp_out) return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "kp_out is NULL");

    zuptsdk_keypair_t *kp = (zuptsdk_keypair_t *)zsdk_calloc(1, sizeof(*kp));
    if (!kp) return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "keypair alloc");

    char priv_buf[512], pub_buf[512];
    zsdk_tmp_path(priv_buf, sizeof(priv_buf), "zsdk_priv");
    zsdk_tmp_path(pub_buf,  sizeof(pub_buf),  "zsdk_pub");

    if (zupt_hybrid_keygen(priv_buf) != 0) {
        zsdk_free_internal(kp);
        return ZSDK_FAIL(ZUPTSDK_ERR_CRYPTO_FAIL, "hybrid_keygen failed");
    }
    if (zupt_hybrid_export_pubkey(priv_buf, pub_buf) != 0) {
        unlink(priv_buf);
        zsdk_free_internal(kp);
        return ZSDK_FAIL(ZUPTSDK_ERR_CRYPTO_FAIL, "export_pubkey failed");
    }
    kp->priv_path = zsdk_strdup(priv_buf);
    kp->pub_path  = zsdk_strdup(pub_buf);
    if (!kp->priv_path || !kp->pub_path) {
        zuptsdk_keypair_destroy(kp);
        return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "path strdup");
    }
    *kp_out = kp;
    return ZUPTSDK_OK;
}

void zuptsdk_keypair_destroy(zuptsdk_keypair_t *kp) {
    if (!kp) return;
    if (kp->priv_path) { unlink(kp->priv_path); zsdk_free_internal(kp->priv_path); }
    if (kp->pub_path)  { unlink(kp->pub_path);  zsdk_free_internal(kp->pub_path); }
    zsdk_free_internal(kp);
}

static int zsdk_copy_file(const char *src, const char *dst, mode_t mode) {
    FILE *fi = fopen(src, "rb");
    if (!fi) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "open %s", src);
    FILE *fo = fopen(dst, "wb");
    if (!fo) { fclose(fi); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "create %s", dst); }
    uint8_t buf[4096];
    size_t n;
    int rc = ZUPTSDK_OK;
    while ((n = fread(buf, 1, sizeof(buf), fi)) > 0)
        if (fwrite(buf, 1, n, fo) != n) { rc = ZSDK_FAIL(ZUPTSDK_ERR_IO, "write %s", dst); break; }
    zuptsdk_secure_zero(buf, sizeof(buf));
    fclose(fi); fclose(fo);
#ifndef _WIN32
    if (rc == ZUPTSDK_OK) chmod(dst, mode);
#else
    (void)mode;
#endif
    return rc;
}

int zuptsdk_keypair_save_private(const zuptsdk_keypair_t *kp, const char *path) {
    if (!kp || !kp->priv_path || !path)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    return zsdk_copy_file(kp->priv_path, path, 0600);
}

int zuptsdk_keypair_save_public(const zuptsdk_keypair_t *kp, const char *path) {
    if (!kp || !kp->pub_path || !path)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    return zsdk_copy_file(kp->pub_path, path, 0644);
}

int zuptsdk_privkey_load(const char *path, zuptsdk_privkey_t **key_out) {
    if (!path || !key_out)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    FILE *f = fopen(path, "rb");
    if (!f) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "open private key %s", path);
    fclose(f);
    zuptsdk_privkey_t *k = (zuptsdk_privkey_t *)zsdk_calloc(1, sizeof(*k));
    if (!k) return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "privkey alloc");
    k->path = zsdk_strdup(path);
    if (!k->path) { zsdk_free_internal(k); return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "path"); }
    *key_out = k;
    return ZUPTSDK_OK;
}

void zuptsdk_privkey_destroy(zuptsdk_privkey_t *key) {
    if (!key) return;
    if (key->path) zsdk_free_internal(key->path);
    zsdk_free_internal(key);
}

int zuptsdk_pubkey_load(const char *path, zuptsdk_pubkey_t **key_out) {
    if (!path || !key_out)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    FILE *f = fopen(path, "rb");
    if (!f) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "open public key %s", path);
    fclose(f);
    zuptsdk_pubkey_t *k = (zuptsdk_pubkey_t *)zsdk_calloc(1, sizeof(*k));
    if (!k) return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "pubkey alloc");
    k->path = zsdk_strdup(path);
    if (!k->path) { zsdk_free_internal(k); return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "path"); }
    *key_out = k;
    return ZUPTSDK_OK;
}

void zuptsdk_pubkey_destroy(zuptsdk_pubkey_t *key) {
    if (!key) return;
    if (key->path) zsdk_free_internal(key->path);
    zsdk_free_internal(key);
}

int zuptsdk_privkey_get_public(const zuptsdk_privkey_t *priv,
                               zuptsdk_pubkey_t **pub_out) {
    if (!priv || !priv->path || !pub_out)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    char tmp[512];
    zsdk_tmp_path(tmp, sizeof(tmp), "zsdk_pub");
    if (zupt_hybrid_export_pubkey(priv->path, tmp) != 0)
        return ZSDK_FAIL(ZUPTSDK_ERR_CRYPTO_FAIL, "export_pubkey failed");
    zuptsdk_pubkey_t *k = (zuptsdk_pubkey_t *)zsdk_calloc(1, sizeof(*k));
    if (!k) { unlink(tmp); return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "pubkey alloc"); }
    k->path = zsdk_strdup(tmp);
    if (!k->path) { unlink(tmp); zsdk_free_internal(k); return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "path"); }
    *pub_out = k;
    return ZUPTSDK_OK;
}

/* ════════════════════════════════════════════════════════════════════════
 * Compress / extract
 * ════════════════════════════════════════════════════════════════════════ */

int zuptsdk_compress_files(zuptsdk_ctx_t *ctx,
                           const zuptsdk_options_t *opts,
                           const char *const *file_paths,
                           size_t file_count,
                           zuptsdk_secure_buf_t *password,
                           const zuptsdk_pubkey_t *recipient_pk,
                           uint8_t **archive_out,
                           size_t *archive_sz) {
    if (!file_paths || !file_count || !archive_out || !archive_sz)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL/empty parameter");

    zupt_options_t zopts;
    zsdk_apply_options(&zopts, opts, ctx);

    int rc = zsdk_apply_password(&zopts, password);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); return rc; }
    rc = zsdk_apply_pubkey(&zopts, recipient_pk);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); return rc; }

    char tmp[512];
    zsdk_tmp_path(tmp, sizeof(tmp), "zsdk_arc");

    /* Build arc/disk path arrays */
    const char **arc_paths  = (const char **)zsdk_calloc(file_count, sizeof(char *));
    const char **disk_paths = (const char **)zsdk_calloc(file_count, sizeof(char *));
    if (!arc_paths || !disk_paths) {
        zsdk_free_internal(arc_paths); zsdk_free_internal(disk_paths);
        zsdk_wipe_options_secrets(&zopts);
        return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "path arrays");
    }
    for (size_t i = 0; i < file_count; i++) {
        disk_paths[i] = file_paths[i];
        const char *base = strrchr(file_paths[i], '/');
        arc_paths[i] = base ? base + 1 : file_paths[i];
    }

    zupt_error_t err = (opts && opts->solid)
        ? zupt_compress_solid(tmp, arc_paths, disk_paths, (int)file_count, &zopts)
        : zupt_compress_files(tmp, arc_paths, disk_paths, (int)file_count, &zopts);

    zsdk_free_internal(arc_paths);
    zsdk_free_internal(disk_paths);
    zsdk_wipe_options_secrets(&zopts);

    if (err != ZUPT_OK) {
        unlink(tmp);
        return ZSDK_FAIL(zsdk_map_zupt_error(err), "compress failed (zupt_err=%d)", err);
    }

    /* Slurp tmp file into output buffer */
    FILE *f = fopen(tmp, "rb");
    if (!f) { unlink(tmp); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "reopen archive"); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); unlink(tmp); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "empty archive"); }

    uint8_t *buf = (uint8_t *)zsdk_malloc((size_t)sz);
    if (!buf) { fclose(f); unlink(tmp); return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "archive buf"); }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    unlink(tmp);
    if (got != (size_t)sz) { zsdk_free_internal(buf); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "short read"); }

    *archive_out = buf;
    *archive_sz  = (size_t)sz;
    return ZUPTSDK_OK;
}

int zuptsdk_compress_buffer(zuptsdk_ctx_t *ctx,
                            const zuptsdk_options_t *opts,
                            const char *logical_name,
                            const uint8_t *data, size_t data_sz,
                            zuptsdk_secure_buf_t *password,
                            const zuptsdk_pubkey_t *recipient_pk,
                            uint8_t **archive_out,
                            size_t *archive_sz) {
    if (!logical_name || !data || !archive_out || !archive_sz)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");

    char tmp_in[512];
    zsdk_tmp_path(tmp_in, sizeof(tmp_in), "zsdk_in");
    FILE *f = fopen(tmp_in, "wb");
    if (!f) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "create temp input");
    if (fwrite(data, 1, data_sz, f) != data_sz) {
        fclose(f); unlink(tmp_in);
        return ZSDK_FAIL(ZUPTSDK_ERR_IO, "write temp input");
    }
    fclose(f);

    zupt_options_t zopts;
    zsdk_apply_options(&zopts, opts, ctx);
    int rc = zsdk_apply_password(&zopts, password);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); unlink(tmp_in); return rc; }
    rc = zsdk_apply_pubkey(&zopts, recipient_pk);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); unlink(tmp_in); return rc; }

    char tmp_arc[512];
    zsdk_tmp_path(tmp_arc, sizeof(tmp_arc), "zsdk_arc");

    const char *arc_paths[1]  = { logical_name };
    const char *disk_paths[1] = { tmp_in };
    zupt_error_t err = zupt_compress_files(tmp_arc, arc_paths, disk_paths, 1, &zopts);

    zsdk_wipe_options_secrets(&zopts);
    unlink(tmp_in);

    if (err != ZUPT_OK) {
        unlink(tmp_arc);
        return ZSDK_FAIL(zsdk_map_zupt_error(err), "compress (zupt_err=%d)", err);
    }

    f = fopen(tmp_arc, "rb");
    if (!f) { unlink(tmp_arc); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "reopen archive"); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)zsdk_malloc((size_t)sz);
    if (!buf) { fclose(f); unlink(tmp_arc); return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "archive buf"); }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    unlink(tmp_arc);
    if (got != (size_t)sz) { zsdk_free_internal(buf); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "short read"); }

    *archive_out = buf;
    *archive_sz  = (size_t)sz;
    return ZUPTSDK_OK;
}

int zuptsdk_extract_to_dir(zuptsdk_ctx_t *ctx,
                           const uint8_t *archive, size_t archive_sz,
                           const char *dest_dir,
                           zuptsdk_secure_buf_t *password,
                           const zuptsdk_privkey_t *recipient_sk) {
    if (!archive || !archive_sz || !dest_dir)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");

    char tmp[512];
    zsdk_tmp_path(tmp, sizeof(tmp), "zsdk_arc");
    FILE *f = fopen(tmp, "wb");
    if (!f) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "write temp archive");
    if (fwrite(archive, 1, archive_sz, f) != archive_sz) {
        fclose(f); unlink(tmp);
        return ZSDK_FAIL(ZUPTSDK_ERR_IO, "write archive");
    }
    fclose(f);

    zupt_options_t zopts;
    zsdk_apply_options(&zopts, NULL, ctx);
    int rc = zsdk_apply_password(&zopts, password);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); unlink(tmp); return rc; }
    rc = zsdk_apply_privkey(&zopts, recipient_sk);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); unlink(tmp); return rc; }

    zupt_error_t err = zupt_extract_archive(tmp, dest_dir, &zopts);
    zsdk_wipe_options_secrets(&zopts);
    unlink(tmp);
    if (err != ZUPT_OK)
        return ZSDK_FAIL(zsdk_map_zupt_error(err), "extract (zupt_err=%d)", err);
    return ZUPTSDK_OK;
}

int zuptsdk_extract_buffer(zuptsdk_ctx_t *ctx,
                           const uint8_t *archive, size_t archive_sz,
                           zuptsdk_secure_buf_t *password,
                           const zuptsdk_privkey_t *recipient_sk,
                           uint8_t **data_out, size_t *data_sz) {
    if (!archive || !archive_sz || !data_out || !data_sz)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");

    char tmpdir[512];
    zsdk_tmp_path(tmpdir, sizeof(tmpdir), "zsdk_x");
    if (zupt_mkdir(tmpdir) != 0)
        return ZSDK_FAIL(ZUPTSDK_ERR_IO, "mkdir %s", tmpdir);

    int rc = zuptsdk_extract_to_dir(ctx, archive, archive_sz, tmpdir, password, recipient_sk);
    if (rc != ZUPTSDK_OK) { rmdir(tmpdir); return rc; }

    /* Find the single file in tmpdir */
#ifdef _WIN32
    /* Simplified: assume one file, use FindFirstFile */
    WIN32_FIND_DATAA fd;
    char pat[600]; snprintf(pat, sizeof(pat), "%s\\*", tmpdir);
    HANDLE h = FindFirstFileA(pat, &fd);
    char fpath[1024] = {0};
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.cFileName[0] != '.') {
                snprintf(fpath, sizeof(fpath), "%s\\%s", tmpdir, fd.cFileName);
                break;
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    DIR *d = opendir(tmpdir);
    char fpath[1024] = {0};
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            snprintf(fpath, sizeof(fpath), "%s/%s", tmpdir, e->d_name);
            break;
        }
        closedir(d);
    }
#endif
    if (!fpath[0]) {
        rmdir(tmpdir);
        return ZSDK_FAIL(ZUPTSDK_ERR_BAD_ARCHIVE, "no extracted file");
    }

    FILE *f = fopen(fpath, "rb");
    if (!f) { unlink(fpath); rmdir(tmpdir); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "open extracted"); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)zsdk_malloc((size_t)sz);
    if (!buf) { fclose(f); unlink(fpath); rmdir(tmpdir); return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "data buf"); }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); unlink(fpath); rmdir(tmpdir); zsdk_free_internal(buf);
        return ZSDK_FAIL(ZUPTSDK_ERR_IO, "read extracted");
    }
    fclose(f);
    unlink(fpath);
    rmdir(tmpdir);
    *data_out = buf;
    *data_sz  = (size_t)sz;
    return ZUPTSDK_OK;
}

/* ════════════════════════════════════════════════════════════════════════
 * Streaming wrappers (initially via tempfile, swap to true streaming later)
 * ════════════════════════════════════════════════════════════════════════ */

static int zsdk_drain_to_file(zuptsdk_read_fn input, void *ud, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "create %s", path);
    uint8_t buf[65536];
    int64_t n;
    while ((n = input(ud, buf, sizeof(buf))) > 0) {
        if (fwrite(buf, 1, (size_t)n, f) != (size_t)n) {
            fclose(f); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "write %s", path);
        }
    }
    zuptsdk_secure_zero(buf, sizeof(buf));
    fclose(f);
    if (n < 0) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "read callback returned %lld", (long long)n);
    return ZUPTSDK_OK;
}

static int zsdk_pump_from_file(zuptsdk_write_fn output, void *ud, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "open %s", path);
    uint8_t buf[65536];
    size_t n;
    int rc = ZUPTSDK_OK;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        int64_t w = output(ud, buf, n);
        if (w != (int64_t)n) { rc = ZSDK_FAIL(ZUPTSDK_ERR_IO, "write callback short %lld", (long long)w); break; }
    }
    zuptsdk_secure_zero(buf, sizeof(buf));
    fclose(f);
    return rc;
}

int zuptsdk_compress_stream(zuptsdk_ctx_t *ctx,
                            const zuptsdk_options_t *opts,
                            zuptsdk_read_fn input, void *input_ud,
                            const char *input_name, uint64_t input_total,
                            zuptsdk_write_fn output, void *output_ud,
                            zuptsdk_secure_buf_t *password,
                            const zuptsdk_pubkey_t *recipient_pk) {
    (void)input_total;
    if (!input || !output || !input_name)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");

    char in_tmp[512], arc_tmp[512];
    zsdk_tmp_path(in_tmp,  sizeof(in_tmp),  "zsdk_in");
    zsdk_tmp_path(arc_tmp, sizeof(arc_tmp), "zsdk_arc");

    int rc = zsdk_drain_to_file(input, input_ud, in_tmp);
    if (rc != ZUPTSDK_OK) { unlink(in_tmp); return rc; }

    zupt_options_t zopts;
    zsdk_apply_options(&zopts, opts, ctx);
    rc = zsdk_apply_password(&zopts, password);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); unlink(in_tmp); return rc; }
    rc = zsdk_apply_pubkey(&zopts, recipient_pk);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); unlink(in_tmp); return rc; }

    const char *arc_paths[1]  = { input_name };
    const char *disk_paths[1] = { in_tmp };
    zupt_error_t err = zupt_compress_files(arc_tmp, arc_paths, disk_paths, 1, &zopts);

    zsdk_wipe_options_secrets(&zopts);
    unlink(in_tmp);

    if (err != ZUPT_OK) {
        unlink(arc_tmp);
        return ZSDK_FAIL(zsdk_map_zupt_error(err), "compress (zupt_err=%d)", err);
    }

    rc = zsdk_pump_from_file(output, output_ud, arc_tmp);
    unlink(arc_tmp);
    return rc;
}

int zuptsdk_decompress_stream(zuptsdk_ctx_t *ctx,
                              zuptsdk_read_fn input, void *input_ud,
                              zuptsdk_write_fn output, void *output_ud,
                              zuptsdk_secure_buf_t *password,
                              const zuptsdk_privkey_t *recipient_sk) {
    if (!input || !output)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");

    char arc_tmp[512];
    zsdk_tmp_path(arc_tmp, sizeof(arc_tmp), "zsdk_arc");
    int rc = zsdk_drain_to_file(input, input_ud, arc_tmp);
    if (rc != ZUPTSDK_OK) { unlink(arc_tmp); return rc; }

    /* Read into memory, call buffer extract */
    FILE *f = fopen(arc_tmp, "rb");
    if (!f) { unlink(arc_tmp); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "reopen archive"); }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *abuf = (uint8_t *)zsdk_malloc((size_t)sz);
    if (!abuf) { fclose(f); unlink(arc_tmp); return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "archive buf"); }
    size_t got = fread(abuf, 1, (size_t)sz, f);
    fclose(f); unlink(arc_tmp);
    if (got != (size_t)sz) { zsdk_free_internal(abuf); return ZSDK_FAIL(ZUPTSDK_ERR_IO, "short read"); }

    uint8_t *data = NULL; size_t data_sz = 0;
    rc = zuptsdk_extract_buffer(ctx, abuf, (size_t)sz, password, recipient_sk, &data, &data_sz);
    zsdk_free_internal(abuf);
    if (rc != ZUPTSDK_OK) return rc;

    int64_t w = output(output_ud, data, data_sz);
    zuptsdk_secure_zero(data, data_sz);
    zsdk_free_internal(data);
    if (w != (int64_t)data_sz) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "write callback short");
    return ZUPTSDK_OK;
}

/* ════════════════════════════════════════════════════════════════════════
 * Verify / info
 * ════════════════════════════════════════════════════════════════════════ */

int zuptsdk_verify(zuptsdk_ctx_t *ctx,
                   const uint8_t *archive, size_t archive_sz,
                   zuptsdk_secure_buf_t *password,
                   const zuptsdk_privkey_t *recipient_sk) {
    if (!archive || !archive_sz)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    char tmp[512];
    zsdk_tmp_path(tmp, sizeof(tmp), "zsdk_v");
    FILE *f = fopen(tmp, "wb");
    if (!f) return ZSDK_FAIL(ZUPTSDK_ERR_IO, "write temp archive");
    fwrite(archive, 1, archive_sz, f); fclose(f);

    zupt_options_t zopts;
    zsdk_apply_options(&zopts, NULL, ctx);
    int rc = zsdk_apply_password(&zopts, password);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); unlink(tmp); return rc; }
    rc = zsdk_apply_privkey(&zopts, recipient_sk);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); unlink(tmp); return rc; }

    zupt_error_t err = zupt_test_archive(tmp, &zopts);
    zsdk_wipe_options_secrets(&zopts);
    unlink(tmp);
    if (err != ZUPT_OK)
        return ZSDK_FAIL(zsdk_map_zupt_error(err), "verify (zupt_err=%d)", err);
    return ZUPTSDK_OK;
}

/* archive_info: minimal v1 — returns header fields parsed from buffer */
struct zuptsdk_archive_info {
    int      format_major;
    int      format_minor;
    char    *uuid_str;     /* heap */
    int64_t  created_unix;
    uint64_t size;
    uint32_t block_count;
    int      is_encrypted;
    int      is_pq_hybrid;
    int      is_solid;
    int      is_dedup;
    int      is_disk_image;
};

int zuptsdk_archive_info_read(zuptsdk_ctx_t *ctx,
                              const uint8_t *archive, size_t archive_sz,
                              zuptsdk_archive_info_t **info_out) {
    (void)ctx;
    if (!archive || !info_out)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    if (archive_sz < 64) return ZSDK_FAIL(ZUPTSDK_ERR_BAD_ARCHIVE, "too small");

    /* Magic check */
    static const uint8_t magic[6] = {
        ZUPT_MAGIC_0, ZUPT_MAGIC_1, ZUPT_MAGIC_2,
        ZUPT_MAGIC_3, ZUPT_MAGIC_4, ZUPT_MAGIC_5 };
    if (memcmp(archive, magic, 6) != 0)
        return ZSDK_FAIL(ZUPTSDK_ERR_BAD_ARCHIVE, "magic mismatch");

    zuptsdk_archive_info_t *i = (zuptsdk_archive_info_t *)zsdk_calloc(1, sizeof(*i));
    if (!i) return ZSDK_FAIL(ZUPTSDK_ERR_NO_MEMORY, "info alloc");

    /* Parse header per format spec: magic[6] | major[1] | minor[1] | flags[4] |
     * uuid[16] | created[8] | reserved[20] = 56 bytes */
    i->format_major = archive[6];
    i->format_minor = archive[7];
    uint32_t flags = (uint32_t)archive[8]      | ((uint32_t)archive[9]  << 8)
                   | ((uint32_t)archive[10]<<16)| ((uint32_t)archive[11] << 24);
    i->is_encrypted   = (flags & ZUPT_FLAG_ENCRYPTED)   != 0;
    i->is_pq_hybrid   = (flags & ZUPT_FLAG_PQ_HYBRID)   != 0;
    i->is_solid       = (flags & ZUPT_FLAG_SOLID)       != 0;
    i->is_dedup       = (flags & ZUPT_FLAG_DEDUP)       != 0;
    i->is_disk_image  = 0; /* heuristic: detect later */

    /* UUID hex string */
    char uuid[37] = {0};
    snprintf(uuid, sizeof(uuid),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             archive[12],archive[13],archive[14],archive[15],
             archive[16],archive[17],archive[18],archive[19],
             archive[20],archive[21],archive[22],archive[23],
             archive[24],archive[25],archive[26],archive[27]);
    i->uuid_str = zsdk_strdup(uuid);

    /* Created timestamp: little-endian uint64 at offset 28 */
    uint64_t ts = 0;
    for (int k = 0; k < 8; k++) ts |= (uint64_t)archive[28 + k] << (k * 8);
    i->created_unix = (int64_t)ts;
    i->size = archive_sz;
    i->block_count = 0; /* would need full parse to count */

    *info_out = i;
    return ZUPTSDK_OK;
}

void zuptsdk_archive_info_destroy(zuptsdk_archive_info_t *info) {
    if (!info) return;
    if (info->uuid_str) zsdk_free_internal(info->uuid_str);
    zsdk_free_internal(info);
}

int      zuptsdk_archive_info_format_major(const zuptsdk_archive_info_t *i) { return i ? i->format_major : 0; }
int      zuptsdk_archive_info_format_minor(const zuptsdk_archive_info_t *i) { return i ? i->format_minor : 0; }
const char *zuptsdk_archive_info_uuid(const zuptsdk_archive_info_t *i)      { return i ? i->uuid_str : ""; }
int64_t  zuptsdk_archive_info_created_unix(const zuptsdk_archive_info_t *i) { return i ? i->created_unix : 0; }
uint64_t zuptsdk_archive_info_size(const zuptsdk_archive_info_t *i)         { return i ? i->size : 0; }
uint32_t zuptsdk_archive_info_block_count(const zuptsdk_archive_info_t *i)  { return i ? i->block_count : 0; }
int      zuptsdk_archive_info_is_encrypted(const zuptsdk_archive_info_t *i) { return i ? i->is_encrypted : 0; }
int      zuptsdk_archive_info_is_pq_hybrid(const zuptsdk_archive_info_t *i) { return i ? i->is_pq_hybrid : 0; }
int      zuptsdk_archive_info_is_solid(const zuptsdk_archive_info_t *i)     { return i ? i->is_solid : 0; }
int      zuptsdk_archive_info_is_dedup(const zuptsdk_archive_info_t *i)     { return i ? i->is_dedup : 0; }
int      zuptsdk_archive_info_is_disk_image(const zuptsdk_archive_info_t *i){ return i ? i->is_disk_image : 0; }

/* ════════════════════════════════════════════════════════════════════════
 * Disk
 * ════════════════════════════════════════════════════════════════════════ */

int zuptsdk_disk_backup(zuptsdk_ctx_t *ctx,
                        const zuptsdk_options_t *opts,
                        const char *source, const char *output,
                        zuptsdk_secure_buf_t *password,
                        const zuptsdk_pubkey_t *recipient_pk) {
    if (!source || !output)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    zupt_options_t zopts;
    zsdk_apply_options(&zopts, opts, ctx);
    int rc = zsdk_apply_password(&zopts, password);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); return rc; }
    rc = zsdk_apply_pubkey(&zopts, recipient_pk);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); return rc; }

    zupt_error_t err = zupt_disk_backup(output, source, &zopts);
    zsdk_wipe_options_secrets(&zopts);
    if (err != ZUPT_OK)
        return ZSDK_FAIL(zsdk_map_zupt_error(err), "disk_backup (zupt_err=%d)", err);
    return ZUPTSDK_OK;
}

int zuptsdk_disk_restore(zuptsdk_ctx_t *ctx,
                         const char *archive_path, const char *target,
                         zuptsdk_secure_buf_t *password,
                         const zuptsdk_privkey_t *recipient_sk) {
    if (!archive_path || !target)
        return ZSDK_FAIL(ZUPTSDK_ERR_INVALID_ARG, "NULL parameter");
    zupt_options_t zopts;
    zsdk_apply_options(&zopts, NULL, ctx);
    int rc = zsdk_apply_password(&zopts, password);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); return rc; }
    rc = zsdk_apply_privkey(&zopts, recipient_sk);
    if (rc != ZUPTSDK_OK) { zsdk_wipe_options_secrets(&zopts); return rc; }

    zupt_error_t err = zupt_disk_restore(archive_path, target, &zopts);
    zsdk_wipe_options_secrets(&zopts);
    if (err != ZUPT_OK)
        return ZSDK_FAIL(zsdk_map_zupt_error(err), "disk_restore (zupt_err=%d)", err);
    return ZUPTSDK_OK;
}
