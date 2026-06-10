/*
 * Zupt — Backup-oriented compression with AES-256 encryption
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef ZUPT_H
#define ZUPT_H

/* Feature test macros — must precede all system includes.
 * _DEFAULT_SOURCE gives us lstat() on glibc without -D_GNU_SOURCE. */
#if !defined(_DEFAULT_SOURCE) && !defined(_GNU_SOURCE)
  #define _DEFAULT_SOURCE 1
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef _WIN32
  #include <windows.h>
  #include <direct.h>
  #define ZUPT_PATH_SEP '\\'
  #define zupt_mkdir(p) _mkdir(p)
#else
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <dirent.h>
  #include <unistd.h>
  #define ZUPT_PATH_SEP '/'
  #define zupt_mkdir(p) mkdir(p, 0755)
#endif

/* ─── Product identity ─────────────────────────────────────────────
 *
 * v3.0.0 (INPI Brasil trademark rename):
 *   - Product name is now "VaptVupt" (was "Zupt"). The earlier name
 *     conflicted with a software trademark already registered at INPI
 *     Brasil under "Zupt".
 *   - File extension stays `.zupt` for archive-format continuity:
 *     v1.0–v2.4.x archives remain readable, the magic bytes
 *     `\x5A\x55\x50\x54\x1A\x00` ("ZUPT" + sub-version) are unchanged.
 *   - C identifier prefix stays `zupt_` / `ZUPT_` for ABI continuity
 *     with libzuptsdk and existing callers. Only user-visible strings
 *     (binary name, banner, help text, package names) change.
 *   - The binary is now `vaptvupt`. Distro packages may ship a
 *     compatibility symlink `zupt -> vaptvupt` for one major version.
 */
#define ZUPT_PRODUCT_NAME      "VaptVupt"
#define ZUPT_PRODUCT_NAME_LC   "vaptvupt"        /* lowercase: binary name */
#define ZUPT_PRODUCT_EXTENSION ".zupt"           /* on-disk archive extension (kept stable) */
#define ZUPT_PRODUCT_TAGLINE   "Post-quantum backup compression"

#define ZUPT_VERSION_STRING "4.0.0"
/* Vendored codec release (upstream tag) — single source for display strings.
 * The codec's own VV_VERSION_* is its internal API version, not the release. */
#define ZUPT_CODEC_RELEASE "2.60.4"
#define ZUPT_FORMAT_MAJOR   1
#define ZUPT_FORMAT_MINOR   6

/* F-08 of v2.3.0: archive-integrity trailer.
 *
 * v1.5 archives append a 32-byte trailing field AFTER the 32-byte footer.
 * Encrypted modes store HMAC-SHA256(mac_key, hdr[0..63] || footer[0..23]).
 * Plaintext modes store XXH64(...) in the first 8 bytes, zeros in the rest.
 *
 * The MAC input excludes footer[24..31] (the "ZEND" magic and footer_version)
 * to keep the field stable across format-version transitions. Both bytes are
 * structurally validated by read_footer().
 *
 * Read path falls back to v1.4 layout (no trailer) when the footer magic is
 * found at EOF-32 instead of EOF-64. */
#define ZUPT_AIT_SIZE       32
#define ZUPT_AIT_MAC_INPUT_LEN  (sizeof(zupt_archive_header_t) + 24)

#define ZUPT_MAGIC_0  0x5A
#define ZUPT_MAGIC_1  0x55
#define ZUPT_MAGIC_2  0x50
#define ZUPT_MAGIC_3  0x54
#define ZUPT_MAGIC_4  0x1A
#define ZUPT_MAGIC_5  0x00
#define ZUPT_BLOCK_MAGIC_0 0xBB
#define ZUPT_BLOCK_MAGIC_1 0x01

#define ZUPT_MAX_PATH         4096
#define ZUPT_MAX_FILES        2000000
#define ZUPT_DEFAULT_BLOCK_SZ (4 * 1024 * 1024)
#define ZUPT_MIN_BLOCK_SZ     (64 * 1024)
#define ZUPT_MAX_BLOCK_SZ     (256 * 1024 * 1024)

/* Global flags */
#define ZUPT_FLAG_ENCRYPTED    (1u << 0)
#define ZUPT_FLAG_CKSUM_XXH64  (0u << 5)
#define ZUPT_FLAG_SOLID        (1u << 1)
#define ZUPT_FLAG_MULTITHREADED (1u << 2) /* Informational: archive was produced with MT */
#define ZUPT_FLAG_PQ_HYBRID    (1u << 3) /* Post-quantum hybrid encryption */
#define ZUPT_FLAG_FORMAT_STABLE (1u << 4) /* v1.0: format frozen */
#define ZUPT_FLAG_DEDUP        (1u << 7) /* Block-level deduplication enabled */
#define ZUPT_FLAG_AAD_SEQ      (1u << 8) /* MAC binds block_seq as AAD (anti-reorder) */
#define ZUPT_FLAG_AAD_PREFACE  (1u << 9) /* v1.6: MAC also binds per-block frame preface (F-09) */

/* Encryption types (stored in encryption header block) */
#define ZUPT_ENC_PBKDF2     0x01  /* Password-based: PBKDF2 → AES-256-CTR + HMAC */
#define ZUPT_ENC_PQ_HYBRID  0x02  /* ML-KEM-768 + X25519 hybrid KEM (legacy XOR+SHA3) */
#define ZUPT_ENC_PQ_SDK_V2  0x03  /* libzuptsdk v2 header: HKDF combiner + commitment + HPKE binding */
#define ZUPT_ENC_PW_ARGON2  0x04  /* Password-based via libzuptsdk: Argon2id + XChaCha20-Poly1305 */
#define ZUPT_ENC_PQ_BOX_V1  0x05  /* libpqvaptvupt sealed box: HKDF-SHA256 domain-separated combiner */

/* Argon2id KDF profile descriptor (v3.4.0).
 *
 * The 0x04 Argon2id enc-header historically recorded only [type|salt|
 * nonce] (33 bytes) and said nothing about the KDF cost parameters,
 * unlike the PBKDF2 header which records its iteration count. That made
 * an 0x04 archive non-self-describing: if the underlying Argon2id cost
 * preset ever changed, old archives could become undecryptable with no
 * way for a reader to know which cost produced them.
 *
 * v3.4.0 appends ONE descriptor byte at offset 33 naming the KDF profile
 * that produced the archive. Readers that understand the byte can select
 * the matching derivation; the legacy reader (which checks enc_hdr_len
 * >= 33 and reads fixed offsets) simply ignores the trailing byte, so
 * existing 33-byte archives and new 34-byte archives both decrypt. The
 * descriptor is covered by the archive-integrity trailer (F-08), so it
 * cannot be stripped or forged without failing authentication.
 *
 * Profile 0 (implicit, absent byte) == the historical libzuptsdk
 * "MODERATE" Argon2id preset reached via zuptsdk_easy_derive_key.
 * Profile 1 is the same derivation with the descriptor made explicit so
 * future profiles (should the cost change) get distinct IDs. */
#define ZUPT_ARGON2_PROFILE_LEGACY   0x00  /* implicit: pre-3.4.0, no descriptor byte */
#define ZUPT_ARGON2_PROFILE_MODERATE 0x01  /* explicit: libzuptsdk MODERATE preset */
#define ZUPT_ARGON2_HDR_LEN_V1       33    /* [type|salt16|nonce16] */
#define ZUPT_ARGON2_HDR_LEN_V2       34    /* + [profile1] */

/* Block types */
#define ZUPT_BLOCK_DATA       0x00
#define ZUPT_BLOCK_INDEX      0x02
#define ZUPT_BLOCK_ENC_HEADER 0x03
#define ZUPT_BLOCK_DEDUP_REF  0x04  /* Dedup reference: payload = 8B offset of original block */
#define ZUPT_BLOCK_COMMENT    0x05  /* v2.4.3: free-form UTF-8 comment, encrypted same as data blocks */

#define ZUPT_MAX_COMMENT_LEN  4096  /* Maximum comment payload size (bytes). */

/* Block flags */
#define ZUPT_BFLAG_ENCRYPTED  (1u << 0)
/* No per-block flag for F-09 — the v1.6 preface-AAD policy is anchored at
 * archive level via ZUPT_FLAG_AAD_PREFACE in global_flags. That flag is
 * itself MAC-protected by the v1.5 archive-integrity-trailer (F-08), so an
 * attacker can't clear it to downgrade. A per-block flag here would be
 * unauthenticated until the per-block MAC was checked, creating a chicken-
 * and-egg gap. */

/* Codec IDs */
#define ZUPT_CODEC_STORE   0x0000
#define ZUPT_CODEC_ZUPT_LZ 0x0008
#define ZUPT_CODEC_ZUPT_LZH 0x0009  /* LZ77 + Huffman */
#define ZUPT_CODEC_ZUPT_LZHP 0x000A /* LZ77 + Huffman + Byte Prediction (default) */
#define ZUPT_CODEC_VAPTVUPT  0x0010 /* VAPTVUPT: VaptVupt LZ + ANS entropy codec */
#define ZUPT_CODEC_AUTO      0xFFFF /* Auto-detect: VaptVupt if AVX2, else LZHP */

/* SIMD decode over-copy guard (bytes).
 *
 * The VaptVupt codec's AVX2 decode hot path over-writes up to 32 bytes
 * past the logical output end (vaptvupt.h: "Copy exactly n bytes, may
 * over-read/write by up to 32 bytes. Caller must ensure sufficient slack
 * in destination."). Every decode output buffer is over-allocated by
 * this many bytes and the padded capacity is passed to the codec so the
 * over-copy lands in owned memory. The reported uncompressed size is
 * unchanged; the slack is never part of the output. 64 > 32 leaves
 * margin for any future SIMD store-width increase (AVX-512 = 64 B).
 * Used by both the single-threaded (zupt_format.c) and parallel
 * (zupt_parallel.c) decode paths. */
#define ZUPT_VV_DECODE_SLACK 64

/* Crypto */
#define ZUPT_SALT_SIZE       32
#define ZUPT_NONCE_SIZE      16
#define ZUPT_HMAC_SIZE       32
#define ZUPT_AES_KEY_SIZE    32
#define ZUPT_KDF_ITERATIONS  600000

typedef enum {
    ZUPT_OK = 0, ZUPT_ERR_IO = -1, ZUPT_ERR_CORRUPT = -2,
    ZUPT_ERR_BAD_MAGIC = -3, ZUPT_ERR_BAD_VERSION = -4,
    ZUPT_ERR_BAD_CHECKSUM = -5, ZUPT_ERR_NOMEM = -6,
    ZUPT_ERR_OVERFLOW = -7, ZUPT_ERR_INVALID = -8,
    ZUPT_ERR_NOT_FOUND = -9, ZUPT_ERR_UNSUPPORTED = -10,
    ZUPT_ERR_AUTH_FAIL = -11,
} zupt_error_t;

/* ─── On-disk (packed LE) ─── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  magic[6];
    uint8_t  version_major, version_minor;
    uint32_t global_flags;
    uint64_t creation_time;
    uint8_t  archive_id[16];
    uint64_t encryption_header_off;
    uint64_t comment_offset;
    uint8_t  reserved[12];
} zupt_archive_header_t; /* 64 bytes */

typedef struct {
    uint64_t index_offset;
    uint64_t total_blocks;
    uint64_t archive_checksum;
    uint8_t  footer_magic[4]; /* "ZEND" */
    uint32_t footer_version;
} zupt_footer_t; /* 32 bytes */
#pragma pack(pop)

/* ─── In-memory ─── */
typedef struct {
    char path[ZUPT_MAX_PATH];
    uint64_t uncompressed_size, compressed_size;
    uint64_t modification_time, content_hash;
    uint64_t first_block_offset;
    uint32_t block_count, attributes;
} zupt_index_entry_t;

typedef struct {
    uint8_t block_type; uint16_t codec_id, block_flags;
    uint64_t uncompressed_size, compressed_size, checksum;
    uint8_t *payload;
} zupt_block_t;

/* Buffer canary for keyring overflow detection */
#define ZUPT_CANARY 0xDEADCAFEBABEFACEULL

typedef struct {
    uint64_t canary_head;                  /* Must equal ZUPT_CANARY */
    uint8_t enc_key[ZUPT_AES_KEY_SIZE];
    uint8_t mac_key[ZUPT_HMAC_SIZE];
    uint8_t salt[ZUPT_SALT_SIZE];
    uint8_t base_nonce[ZUPT_NONCE_SIZE];
    uint32_t iterations;
    int active;
    uint64_t canary_tail;                  /* Must equal ZUPT_CANARY */
    int use_preface_aad;                   /* F-09 of v2.3.1: appended after canary so existing field layout is preserved */
} zupt_keyring_t;

/* Check keyring canaries — abort on buffer overflow */
static inline void zupt_keyring_init(zupt_keyring_t *kr) {
    volatile uint8_t *p = (volatile uint8_t *)kr;
    for (size_t i = 0; i < sizeof(*kr); i++) p[i] = 0;
    kr->canary_head = ZUPT_CANARY;
    kr->canary_tail = ZUPT_CANARY;
}
static inline void zupt_keyring_check(const zupt_keyring_t *kr) {
    if (kr->canary_head != ZUPT_CANARY || kr->canary_tail != ZUPT_CANARY) {
        fprintf(stderr, "FATAL: keyring buffer overflow detected (canary corrupted)\n");
        /* Use exit(127) instead of abort() to avoid needing <stdlib.h> */
        _exit(127);
    }
}

typedef struct {
    char **paths, **arc_paths;
    int count, capacity;
} zupt_filelist_t;

typedef struct {
    int level; uint32_t block_size; uint16_t codec_id;
    int verbose, encrypt, quiet, solid, threads;
    int pq_mode;           /* 1 = post-quantum hybrid KEM mode */
    int sdk_mode;          /* 1 = use libzuptsdk-backed v3 crypto (HKDF combiner + commitment + HPKE) */
    int box_mode;          /* 1 = libpqvaptvupt sealed-box mode (ZUPT_ENC_PQ_BOX_V1) */
    int dedup;             /* 1 = block-level deduplication enabled */
    int kdf_legacy_pbkdf2; /* v2.4.1: 1 = force PBKDF2-SHA256 enc-header (compat with v2.4.0 and older readers). Default 0 = Argon2id. */
    char password[256];
    char keyfile[ZUPT_MAX_PATH]; /* Path to .zupt-key file */
    char comment[ZUPT_MAX_COMMENT_LEN]; /* v2.4.3: free-form archive comment, encrypted on write if -e */
    int has_comment;             /* v2.4.3: 1 = a comment was supplied (write side) or read from archive (read side) */
    zupt_keyring_t keyring;
} zupt_options_t;

/* ═══════════════════════════════════════════════════════════════════
 * PORTABLE LITTLE-ENDIAN SERIALIZATION
 *
 * All multi-byte fields in the on-disk format are stored as LE.
 * These helpers ensure correct behaviour on both LE and BE hosts.
 * ═══════════════════════════════════════════════════════════════════ */

static inline void zupt_le16_put(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}
static inline void zupt_le32_put(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}
static inline void zupt_le64_put(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}
static inline uint16_t zupt_le16_get(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t zupt_le32_get(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t zupt_le64_get(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* ═══════════════════════════════════════════════════════════════════
 * SECURE MEMORY WIPE (resists dead-store elimination by compilers)
 * ═══════════════════════════════════════════════════════════════════ */

/* FRAMA-C: Secure memory wipe — resists dead-store elimination */
/*@ requires \valid((uint8_t *)ptr + (0..len-1));
  @ assigns ((uint8_t *)ptr)[0..len-1];
  @ ensures \forall integer i; 0 <= i < len ==> ((uint8_t *)ptr)[i] == 0;
*/
static inline void zupt_secure_wipe(void *ptr, size_t len) {
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#elif (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
    extern void explicit_bzero(void *, size_t);
    explicit_bzero(ptr, len);
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
    extern void explicit_bzero(void *, size_t);
    explicit_bzero(ptr, len);
#else
    volatile uint8_t *vp = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) vp[i] = 0;
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * REGULAR-FILE CHECK (skip symlinks, devices, FIFOs, sockets)
 * ═══════════════════════════════════════════════════════════════════ */

static inline int zupt_is_regular_file(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;
    return !(attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE |
                     FILE_ATTRIBUTE_REPARSE_POINT));
#else
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
#endif
}

/* ─── Solid-mode compression ─── */
zupt_error_t zupt_compress_solid(const char *out, const char **arc, const char **disk, int n, zupt_options_t *opts);

/* ─── SHA-256 ─── */
typedef struct { uint32_t state[8]; uint64_t count; uint8_t buf[64]; } zupt_sha256_ctx;
void zupt_sha256_init(zupt_sha256_ctx *c);
void zupt_sha256_update(zupt_sha256_ctx *c, const uint8_t *d, size_t n);
void zupt_sha256_final(zupt_sha256_ctx *c, uint8_t h[32]);
void zupt_sha256(const uint8_t *d, size_t n, uint8_t h[32]);
/* SHA-NI hardware compression function (x86_64; src/zupt_sha256_shani.c).
 * Processes `blocks` full 64-byte blocks, updating state[8] in place.
 * Internal: called by zupt_sha256_update() only when zupt_cpu.has_shani. */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
void zupt_sha256_transform_shani(uint32_t state[8], const uint8_t *data, size_t blocks);
#endif

/* ─── AES-256 ─── */
typedef struct { uint32_t rk[60]; } zupt_aes256_ctx;
void zupt_aes256_init(zupt_aes256_ctx *c, const uint8_t key[32]);
void zupt_aes256_encrypt_block(const zupt_aes256_ctx *c, const uint8_t in[16], uint8_t out[16]);

/* ─── Crypto ops ─── */
void zupt_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen, uint8_t mac[32]);

/* Incremental HMAC-SHA256 (RFC 2104).
 *
 * For repeated MACs under the SAME key (the per-block Encrypt-then-MAC
 * hot path), this folds the ipad/opad key-prefix compression ONCE in
 * _init and lets the caller stream the message via _update — avoiding
 * both the per-call key-pad recompute and any concat/copy buffer for
 * the message segments. Bit-identical output to the one-shot
 * zupt_hmac_sha256 (which is itself implemented on top of this). */
typedef struct {
    zupt_sha256_ctx inner;   /* SHA-256 state seeded with the ipad block */
    zupt_sha256_ctx outer;   /* SHA-256 state seeded with the opad block */
} zupt_hmac_ctx;
void zupt_hmac_sha256_init(zupt_hmac_ctx *c, const uint8_t *key, size_t klen);
void zupt_hmac_sha256_update(zupt_hmac_ctx *c, const uint8_t *data, size_t dlen);
void zupt_hmac_sha256_final(zupt_hmac_ctx *c, uint8_t mac[32]);

/* Constant-time buffer equality. Returns 1 if equal, 0 otherwise, in
 * time dependent only on n (not contents / mismatch position). The single
 * audited MAC-tag comparison primitive; timing-verified by the
 * dudect-style test in tests/test_ct_timing.c. CT-REQUIRED. */
int zupt_ct_memeq(const void *a, const void *b, size_t n);
void zupt_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t slen, uint32_t iter, uint8_t *out, size_t olen);
void zupt_aes256_ctr(const uint8_t key[32], const uint8_t nonce[16], const uint8_t *in, uint8_t *out, size_t len);
void zupt_derive_keys(zupt_keyring_t *kr, const char *pw, const uint8_t salt[32], const uint8_t nonce[16], uint32_t iter);
uint8_t *zupt_encrypt_buffer(const zupt_keyring_t *kr, const uint8_t *plain, size_t plen, uint64_t seq, size_t *olen);
uint8_t *zupt_decrypt_buffer(const zupt_keyring_t *kr, const uint8_t *pkg, size_t pkglen, uint64_t seq, size_t *olen);

/* F-09 of v2.3.1: extended-AAD variants. The MAC input becomes
 * aad_extra || nonce || ciphertext || aad_seq, which lets the caller bind
 * the per-block frame preface (block_type, codec_id, block_flags, sizes,
 * checksum) into the per-block HMAC without changing the on-disk payload
 * layout. v1.6 archives use these; older archives keep using the original
 * functions. */
uint8_t *zupt_encrypt_buffer_aad(const zupt_keyring_t *kr,
                                  const uint8_t *plain, size_t plen,
                                  uint64_t seq,
                                  const uint8_t *aad_extra, size_t aad_extra_len,
                                  size_t *olen);
uint8_t *zupt_decrypt_buffer_aad(const zupt_keyring_t *kr,
                                  const uint8_t *pkg, size_t pkglen,
                                  uint64_t seq,
                                  const uint8_t *aad_extra, size_t aad_extra_len,
                                  size_t *olen);
void zupt_random_bytes(uint8_t *buf, size_t len);

/* ─── Memory locking for key material ─── */
int  zupt_mlock_keys(void *ptr, size_t len);
void zupt_munlock_keys(void *ptr, size_t len);

/* ─── Adaptive compression: file type detection ─── */
/* Returns: -1=store (incompressible), 0=default, 5=medium, 9=max */
int zupt_detect_filetype(const uint8_t *header, size_t header_len);

/* ─── XXH64 ─── */
uint64_t zupt_xxh64(const void *data, size_t len, uint64_t seed);

/* ─── LZ ─── */
size_t zupt_lz_compress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dcap, int level);
size_t zupt_lz_decompress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dlen);
size_t zupt_lz_bound(size_t slen);

/* ─── LZH (LZ77 + Huffman) ─── */
size_t zupt_lzh_compress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dcap, int level);
size_t zupt_lzh_decompress(const uint8_t *src, size_t slen, uint8_t *dst, size_t dlen);
size_t zupt_lzh_bound(size_t slen);

/* ─── Byte Prediction (order-1 context transform) ─── */
void  zupt_predict_build(const uint8_t *data, size_t len, uint8_t prediction[256]);
void  zupt_predict_encode(const uint8_t *in, uint8_t *out, size_t len, const uint8_t pred[256]);
void  zupt_predict_decode(const uint8_t *in, uint8_t *out, size_t len, const uint8_t pred[256]);
float zupt_predict_benefit(const uint8_t *data, size_t len);

/* ─── Format I/O ─── */
int zupt_write_varint(FILE *f, uint64_t v);
int zupt_read_varint(FILE *f, uint64_t *v);
int zupt_encode_varint(uint8_t *b, uint64_t v);
int zupt_decode_varint(const uint8_t *b, size_t blen, uint64_t *v);

void zupt_filelist_init(zupt_filelist_t *fl);
void zupt_filelist_free(zupt_filelist_t *fl);
void zupt_filelist_add(zupt_filelist_t *fl, const char *disk_path, const char *arc_path);
void zupt_collect_files(zupt_filelist_t *fl, const char *path, const char *base);

zupt_error_t zupt_compress_files(const char *out, const char **arc, const char **disk, int n, zupt_options_t *opts);
zupt_error_t zupt_extract_archive(const char *arc, const char *dir, zupt_options_t *opts);
zupt_error_t zupt_list_archive(const char *arc, zupt_options_t *opts);
zupt_error_t zupt_test_archive(const char *arc, zupt_options_t *opts);

/* ─── Hybrid PQ KEM (ML-KEM-768 + X25519) ─── */
int zupt_hybrid_keygen(const char *keyfile);
int zupt_hybrid_export_pubkey(const char *privfile, const char *pubfile);
int zupt_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                              uint8_t *enc_hdr, size_t *enc_hdr_len);
int zupt_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                              const uint8_t *enc_hdr, size_t enc_hdr_len);

/* ─── SDK-backed crypto (zupt v2.2+, libzuptsdk under the hood) ─── */
int zupt_sdk_hybrid_keygen(const char *privkeyfile, const char *pubkeyfile);
int zupt_sdk_hybrid_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                                  uint8_t *enc_hdr, size_t *enc_hdr_len);
int zupt_sdk_hybrid_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                                  const uint8_t *enc_hdr, size_t enc_hdr_len);

/* pq-box mode (ZUPT_ENC_PQ_BOX_V1, vendored libpqvaptvupt) */
int zupt_pqbox_keygen(const char *privkeyfile, const char *pubkeyfile);
int zupt_pqbox_encrypt_init(zupt_keyring_t *kr, const char *pubkeyfile,
                            uint8_t *enc_hdr, size_t *enc_hdr_len);
int zupt_pqbox_decrypt_init(zupt_keyring_t *kr, const char *privkeyfile,
                            const uint8_t *payload, size_t payload_len);
int zupt_sdk_password_encrypt_init(zupt_keyring_t *kr, const char *password,
                                    uint8_t *enc_hdr, size_t *enc_hdr_len);
int zupt_sdk_password_decrypt_init(zupt_keyring_t *kr, const char *password,
                                    const uint8_t *enc_hdr, size_t enc_hdr_len);

const char *zupt_strerror(zupt_error_t e);
const char *zupt_codec_name(uint16_t id);
void zupt_default_options(zupt_options_t *o);
void zupt_format_size(uint64_t bytes, char *buf, size_t cap);

/* Resolve ZUPT_CODEC_AUTO to a concrete codec based on hardware.
 * On x86_64 with AVX2: VaptVupt (fast ANS+SIMD decode).
 * On all other arches:  Zupt-LZHP (no SIMD dependency).
 * Decompression of ALL codecs works on ALL architectures. */
uint16_t zupt_resolve_auto_codec(void);

/* ─── Full-Disk Backup/Restore ─── */
#define ZUPT_FLAG_DISK_IMAGE   (1u << 6)  /* Archive contains a raw disk/partition image */

/* Compress a raw block device or file as a disk image.
 * Reads source in block_size chunks, detects zero/sparse regions,
 * compresses non-zero blocks. Supports encryption + PQ. */
zupt_error_t zupt_disk_backup(const char *output_path, const char *source_path,
                               zupt_options_t *opts);

/* Restore a disk image archive to a block device or file.
 * Writes blocks sequentially, restoring sparse regions as zeros. */
zupt_error_t zupt_disk_restore(const char *archive_path, const char *target_path,
                                zupt_options_t *opts);

/* ─── Internal Block I/O (used by format + disk modules) ─── */
zupt_error_t read_block(FILE *f, zupt_block_t *b);
zupt_error_t read_enc_header(FILE *f, zupt_archive_header_t *hdr, zupt_options_t *opts);
zupt_error_t decompress_block(const zupt_block_t *b, const zupt_keyring_t *kr,
                               uint64_t block_seq, uint8_t **out, size_t *olen);
zupt_error_t write_enc_header(FILE *out, zupt_archive_header_t *hdr,
                               zupt_options_t *opts);
int zupt_w8(FILE *f, uint8_t v);
int zupt_w16le(FILE *f, uint16_t v);
int zupt_w64le(FILE *f, uint64_t v);

/* ─── Block-Level Deduplication ─── */
#define ZUPT_DEDUP_MAX_ENTRIES  (2 * 1024 * 1024)  /* 2M entries, ~48MB RAM */

typedef struct zupt_dedup_ctx zupt_dedup_ctx_t;

zupt_dedup_ctx_t *zupt_dedup_init(void);
void zupt_dedup_free(zupt_dedup_ctx_t *ctx);
int  zupt_dedup_lookup(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                       uint64_t *ref_offset, uint32_t *ref_size);
int  zupt_dedup_insert(zupt_dedup_ctx_t *ctx, uint64_t fingerprint,
                       uint64_t block_offset, uint32_t block_size);
void zupt_dedup_record_hit(zupt_dedup_ctx_t *ctx, uint64_t saved_bytes);
void zupt_dedup_record_block(zupt_dedup_ctx_t *ctx);
void zupt_dedup_stats(const zupt_dedup_ctx_t *ctx,
                      uint64_t *blocks_seen, uint64_t *blocks_deduped,
                      uint64_t *bytes_saved);
int  zupt_dedup_write_ref(FILE *out, uint64_t ref_offset,
                          uint32_t orig_size, uint64_t orig_checksum);

/* ─── Archive Info (read-only metadata inspection) ─── */
zupt_error_t zupt_archive_info(const char *path);

#endif /* ZUPT_H */
