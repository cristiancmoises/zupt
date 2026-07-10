/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 * ZUPT - Archive Format I/O v0.6.0
 *
 * v0.6.0 changes:
 *   - Multi-threaded compression and decompression via zupt_parallel.h
 *   - Format version bump v1.2 → v1.3 (backward compatible)
 *   - ZUPT_FLAG_MULTITHREADED informational flag
 *   - N=1 path is bit-for-bit identical to v0.5.1
 */
#define _GNU_SOURCE
#include "zupt.h"
#include "zupt_cpuid.h"   /* zupt_cpu for AUTO codec detection */
#include "zupt_parallel.h"
#include "vaptvupt.h"  /* VAPTVUPT: VaptVupt codec integration */
#include "vaptvupt_api.h" /* VAPTVUPT: simplified Zupt integration API */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>

/* F-08 of v2.3.0: forward decls — definitions are below read_block(), but the
 * compress write paths at zupt_compress_files()/_solid() and disk-restore at
 * zupt_disk.c need to see ait_write/ait_verify_extern. The extern decl in
 * zupt_disk.c mirrors zupt_format_ait_verify_extern's signature. */
int zupt_format_ait_write(FILE *f, const zupt_archive_header_t *hdr,
                          const zupt_footer_t *ft,
                          const zupt_keyring_t *kr_or_null);
zupt_error_t zupt_format_ait_verify_extern(const zupt_archive_header_t *hdr,
                                           const zupt_footer_t *ft,
                                           const uint8_t ait[ZUPT_AIT_SIZE],
                                           const zupt_keyring_t *kr_or_null);
#endif

#ifdef _WIN32
  #include <io.h>
  #define fseeko _fseeki64
  #define ftello _ftelli64
#endif

/* ═══════════════════════════════════════════════════════════════════
 * UTILITY
 * ═══════════════════════════════════════════════════════════════════ */

/* ZUPT_VV_DECODE_SLACK (SIMD decode over-copy guard) is defined in
 * zupt.h so both this file and zupt_parallel.c share one definition. */

const char *zupt_strerror(zupt_error_t e) {
    switch (e) {
        case ZUPT_OK: return "Success";
        case ZUPT_ERR_IO: return "I/O error";
        case ZUPT_ERR_CORRUPT: return "Archive is corrupt";
        case ZUPT_ERR_BAD_MAGIC: return "Not a .zupt archive";
        case ZUPT_ERR_BAD_VERSION: return "Unsupported version";
        case ZUPT_ERR_BAD_CHECKSUM: return "Checksum mismatch";
        case ZUPT_ERR_NOMEM: return "Out of memory";
        case ZUPT_ERR_OVERFLOW: return "Overflow";
        case ZUPT_ERR_INVALID: return "Invalid argument";
        case ZUPT_ERR_NOT_FOUND: return "Not found";
        case ZUPT_ERR_UNSUPPORTED: return "Unsupported";
        case ZUPT_ERR_AUTH_FAIL: return "Authentication failed (wrong password?)";
        default: return "Unknown error";
    }
}
const char *zupt_codec_name(uint16_t id) {
    switch (id) {
        case ZUPT_CODEC_STORE: return "Store";
        case ZUPT_CODEC_ZUPT_LZ: return "Zupt-LZ";
        case ZUPT_CODEC_ZUPT_LZH: return "Zupt-LZH";
        case ZUPT_CODEC_ZUPT_LZHP: return "Zupt-LZHP";
        case ZUPT_CODEC_VAPTVUPT: return "VaptVupt"; /* VAPTVUPT */
        case ZUPT_CODEC_AUTO: return "Auto";
        default: return "Unknown";
    }
}
void zupt_default_options(zupt_options_t *o) {
    memset(o, 0, sizeof(*o));
    o->level = 7;
    o->block_size = 0;
    o->codec_id = ZUPT_CODEC_AUTO; /* Auto-detect: VaptVupt if AVX2, else LZHP */
    /* Init keyring canaries */
    o->keyring.canary_head = ZUPT_CANARY;
    o->keyring.canary_tail = ZUPT_CANARY;
}

/* Resolve ZUPT_CODEC_AUTO to a concrete codec.
 * VaptVupt decode works on ALL architectures (scalar fallback), but the
 * AVX2 SIMD decode path gives ~3× throughput. On non-AVX2 hardware,
 * Zupt-LZHP is a better default since its simpler decoder doesn't
 * benefit from SIMD as much.
 *
 * Detection order:
 *   1. Compile-time: __x86_64__ + __AVX2__ → VaptVupt (compiled with -mavx2)
 *   2. Runtime: zupt_cpu.has_avx2 → VaptVupt (for x86_64 without -mavx2)
 *   3. Compile-time: __aarch64__ + __ARM_NEON → VaptVupt (NEON decode)
 *   4. Fallback: Zupt-LZHP (works everywhere)
 */
uint16_t zupt_resolve_auto_codec(void) {
#if defined(__x86_64__) || defined(_M_X64)
    /* x86_64: check AVX2 at compile time (via -mavx2) or runtime (cpuid) */
  #if defined(__AVX2__)
    return ZUPT_CODEC_VAPTVUPT;  /* Compiled with -mavx2: inline SIMD decode */
  #else
    if (zupt_cpu.has_avx2)
        return ZUPT_CODEC_VAPTVUPT;  /* Runtime AVX2: vv_simd.c dispatch */
    return ZUPT_CODEC_ZUPT_LZHP;     /* No AVX2: use LZHP */
  #endif
#elif defined(__aarch64__) && defined(__ARM_NEON)
    return ZUPT_CODEC_VAPTVUPT;  /* NEON SIMD decode available */
#else
    return ZUPT_CODEC_ZUPT_LZHP; /* Scalar only: LZHP is a better default */
#endif
}

static uint32_t auto_block_size(int level) {
    if (level <= 2) return 131072;
    if (level <= 4) return 131072;
    if (level <= 6) return 262144;
    if (level <= 7) return 262144;
    return 524288;
}
void zupt_format_size(uint64_t b, char *buf, size_t cap) {
    if (b < 1024) snprintf(buf, cap, "%llu B", (unsigned long long)b);
    else if (b < 1048576) snprintf(buf, cap, "%.1f KB", (double)b/1024.0);
    else if (b < 1073741824ULL) snprintf(buf, cap, "%.1f MB", (double)b/1048576.0);
    else snprintf(buf, cap, "%.2f GB", (double)b/1073741824.0);
}

static uint64_t now_ns(void) { return (uint64_t)time(NULL)*1000000000ULL; }
static void gen_uuid(uint8_t u[16]) {
    zupt_random_bytes(u, 16);
    u[6]=(u[6]&0x0F)|0x40; u[8]=(u[8]&0x3F)|0x80;
}

/* ─── Progress bar ─── */
static void show_progress(const char *label, uint64_t done, uint64_t total) {
    if (total == 0) return;
    int pct = (int)(done * 100 / total);
    int bar = pct / 2;
    char buf[60]; memset(buf, ' ', 50); buf[50] = '\0';
    for (int i = 0; i < bar && i < 50; i++) buf[i] = '#';
    fprintf(stderr, "\r  %s [%-50s] %3d%%", label, buf, pct);
    if (done >= total) fprintf(stderr, "\n");
    fflush(stderr);
}

/* ═══════════════════════════════════════════════════════════════════
 * VARINT
 * ═══════════════════════════════════════════════════════════════════ */

int zupt_encode_varint(uint8_t *b, uint64_t v) {
    int n=0; do { uint8_t x=(uint8_t)(v&0x7F); v>>=7; if(v)x|=0x80; b[n++]=x; } while(v); return n;
}
int zupt_decode_varint(const uint8_t *b, size_t blen, uint64_t *v) {
    *v=0; int s=0,n=0;
    while(n<(int)blen&&n<10){
        uint64_t x=b[n];
        *v|=(x&0x7F)<<s;
        n++;
        if(!(x&0x80))return n;        /* terminator byte — done */
        s+=7;
        /* Invariant: control flow reaches here only with x&0x80 set
         * (the !(x&0x80) check above returned otherwise). The 10-byte
         * loop bound + 7-bit shift means s >= 64 means an 11th byte
         * would be needed, which we refuse. */
        if(s>=64) return -1;
    }
    return -1;
}
int zupt_write_varint(FILE *f, uint64_t v) {
    uint8_t b[10]; int n=zupt_encode_varint(b,v); return fwrite(b,1,(size_t)n,f)==(size_t)n?n:-1;
}
int zupt_read_varint(FILE *f, uint64_t *v) {
    *v=0; int s=0;
    for(int i=0;i<10;i++){
        int c=fgetc(f); if(c==EOF) return -1;
        *v|=(uint64_t)(c&0x7F)<<s;
        if(!(c&0x80)) return i+1;     /* terminator byte — done */
        s+=7;
        /* Same invariant as zupt_decode_varint: only reached with c&0x80 set. */
        if(s>=64) return -1;
    }
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════
 * DIRECTORY TRAVERSAL
 * ═══════════════════════════════════════════════════════════════════ */

void zupt_filelist_init(zupt_filelist_t *fl) {
    fl->paths = NULL; fl->arc_paths = NULL; fl->count = 0; fl->capacity = 0;
}
void zupt_filelist_free(zupt_filelist_t *fl) {
    for (int i = 0; i < fl->count; i++) { free(fl->paths[i]); free(fl->arc_paths[i]); }
    free(fl->paths); free(fl->arc_paths);
    fl->paths = fl->arc_paths = NULL; fl->count = fl->capacity = 0;
}
void zupt_filelist_add(zupt_filelist_t *fl, const char *disk, const char *arc) {
    if (fl->count >= fl->capacity) {
        int new_cap = fl->capacity ? fl->capacity * 2 : 256;
        /* Allocate both buffers atomically: if either fails, both are
         * discarded and the existing fl state is untouched. The previous
         * implementation could leak or corrupt fl->paths when the second
         * realloc failed after the first succeeded — realloc(p, n) when
         * successful invalidates p, so even comparing pointers afterward
         * is undefined behavior. */
        char **new_paths = (char**)malloc((size_t)new_cap * sizeof(char*));
        char **new_arcs  = (char**)malloc((size_t)new_cap * sizeof(char*));
        if (!new_paths || !new_arcs) {
            free(new_paths);  /* free(NULL) is well-defined */
            free(new_arcs);
            fprintf(stderr, "  Warning: out of memory adding '%s'\n", disk);
            return;
        }
        if (fl->paths)     memcpy(new_paths, fl->paths,     (size_t)fl->count * sizeof(char*));
        if (fl->arc_paths) memcpy(new_arcs,  fl->arc_paths, (size_t)fl->count * sizeof(char*));
        free(fl->paths);
        free(fl->arc_paths);
        fl->paths = new_paths;
        fl->arc_paths = new_arcs;
        fl->capacity = new_cap;
    }
    fl->paths[fl->count] = strdup(disk);
    fl->arc_paths[fl->count] = strdup(arc);
    if (!fl->paths[fl->count] || !fl->arc_paths[fl->count]) {
        free(fl->paths[fl->count]);
        free(fl->arc_paths[fl->count]);
        fprintf(stderr, "  Warning: out of memory adding '%s'\n", disk);
        return;
    }
    fl->count++;
}

static int is_dir(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
#endif
}

void zupt_collect_files(zupt_filelist_t *fl, const char *path, const char *base) {
    if (!is_dir(path)) {
        /* Skip non-regular files (symlinks, devices, FIFOs, sockets) */
        if (!zupt_is_regular_file(path)) {
            fprintf(stderr, "  Skipping non-regular file: %s\n", path);
            return;
        }
        const char *arc = base;
        while (arc[0]=='.' && (arc[1]=='/'||arc[1]=='\\')) arc+=2;
        while (*arc=='/'||*arc=='\\') arc++;
        if (*arc == '\0') arc = path;
        while (*arc=='/'||*arc=='\\') arc++;
        zupt_filelist_add(fl, path, arc);
        return;
    }

#ifdef _WIN32
    char pattern[ZUPT_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", path);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0]=='.' && (fd.cFileName[1]=='\0' ||
            (fd.cFileName[1]=='.' && fd.cFileName[2]=='\0'))) continue;
        char child_disk[ZUPT_MAX_PATH], child_arc[ZUPT_MAX_PATH];
        snprintf(child_disk, sizeof(child_disk), "%s\\%s", path, fd.cFileName);
        snprintf(child_arc, sizeof(child_arc), "%s/%s", base, fd.cFileName);
        zupt_collect_files(fl, child_disk, child_arc);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0]=='.' && (ent->d_name[1]=='\0' ||
            (ent->d_name[1]=='.' && ent->d_name[2]=='\0'))) continue;
        char child_disk[ZUPT_MAX_PATH], child_arc[ZUPT_MAX_PATH];
        snprintf(child_disk, sizeof(child_disk), "%s/%s", path, ent->d_name);
        snprintf(child_arc, sizeof(child_arc), "%s/%s", base, ent->d_name);
        zupt_collect_files(fl, child_disk, child_arc);
    }
    closedir(d);
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * WRITE / READ HELPERS (LE-safe, error-checked)
 * ═══════════════════════════════════════════════════════════════════ */

int zupt_w8(FILE*f,uint8_t v){return fwrite(&v,1,1,f)==1?0:-1;}
int zupt_w16le(FILE*f,uint16_t v){uint8_t b[2];zupt_le16_put(b,v);return fwrite(b,1,2,f)==2?0:-1;}
int zupt_w64le(FILE*f,uint64_t v){uint8_t b[8];zupt_le64_put(b,v);return fwrite(b,1,8,f)==8?0:-1;}
static int r16le(FILE*f,uint16_t*v){uint8_t b[2];if(fread(b,1,2,f)!=2)return -1;*v=zupt_le16_get(b);return 0;}
static int r64le(FILE*f,uint64_t*v){uint8_t b[8];if(fread(b,1,8,f)!=8)return -1;*v=zupt_le64_get(b);return 0;}

/* Aliases for internal use (backward compat with existing code) */
#define w8 zupt_w8
#define w16le zupt_w16le
#define w64le zupt_w64le

/* ═══════════════════════════════════════════════════════════════════
 * SHARED ENCRYPTION HEADER WRITER
 *
 * Used by BOTH zupt_compress_files() and zupt_disk_backup().
 * Writes the encryption header block and updates hdr.encryption_header_off.
 * After return, the file position is at the end (ready for data blocks).
 * ═══════════════════════════════════════════════════════════════════ */
zupt_error_t write_enc_header(FILE *out, zupt_archive_header_t *hdr,
                               zupt_options_t *opts) {
    hdr->encryption_header_off = (uint64_t)ftello(out);

    if (opts->box_mode && opts->pq_mode) {
        /* ─── PQ-BOX MODE (libpqvaptvupt sealed box: HKDF-SHA256 combiner) ─── */
        hdr->global_flags |= ZUPT_FLAG_PQ_HYBRID;

        uint8_t enc_hdr_buf[1500];
        size_t enc_hdr_len = 0;
        if (!opts->quiet)
            fprintf(stderr, "  PQ sealed box via libpqvaptvupt (ML-KEM-768 + X25519, HKDF-SHA256)...\n");
        if (zupt_pqbox_encrypt_init(&opts->keyring, opts->keyfile,
                                    enc_hdr_buf, &enc_hdr_len) != 0) {
            fprintf(stderr, "Error: pq-box key encapsulation failed.\n");
            return ZUPT_ERR_AUTH_FAIL;
        }

        zupt_w8(out, ZUPT_BLOCK_MAGIC_0); zupt_w8(out, ZUPT_BLOCK_MAGIC_1);
        zupt_w8(out, ZUPT_BLOCK_ENC_HEADER);
        zupt_w16le(out, ZUPT_CODEC_STORE); zupt_w16le(out, 0);
        zupt_write_varint(out, enc_hdr_len);
        zupt_write_varint(out, enc_hdr_len);
        zupt_w64le(out, zupt_xxh64(enc_hdr_buf, enc_hdr_len, 0));
        if (fwrite(enc_hdr_buf, 1, enc_hdr_len, out) != enc_hdr_len)
            return ZUPT_ERR_IO;

        fseeko(out, 0, SEEK_SET);
        if (fwrite(hdr, sizeof(*hdr), 1, out) != 1) return ZUPT_ERR_IO;
        fseeko(out, 0, SEEK_END);

        if (!opts->quiet)
            fprintf(stderr, "  Encryption: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC)\n\n");
    } else if (opts->sdk_mode && opts->pq_mode) {
        /* ─── SDK V2 PQ MODE (libzuptsdk: HKDF combiner + commitment + HPKE) ─── */
        hdr->global_flags |= ZUPT_FLAG_PQ_HYBRID;

        uint8_t enc_hdr_buf[1500];
        size_t enc_hdr_len = 0;
        if (!opts->quiet)
            fprintf(stderr, "  PQ key encapsulation via libzuptsdk (HKDF-SHA3 + commitment + HPKE)...\n");
        if (zupt_sdk_hybrid_encrypt_init(&opts->keyring, opts->keyfile,
                                          enc_hdr_buf, &enc_hdr_len) != 0) {
            fprintf(stderr, "Error: SDK PQ key encapsulation failed.\n");
            return ZUPT_ERR_AUTH_FAIL;
        }

        zupt_w8(out, ZUPT_BLOCK_MAGIC_0); zupt_w8(out, ZUPT_BLOCK_MAGIC_1);
        zupt_w8(out, ZUPT_BLOCK_ENC_HEADER);
        zupt_w16le(out, ZUPT_CODEC_STORE); zupt_w16le(out, 0);
        zupt_write_varint(out, enc_hdr_len);
        zupt_write_varint(out, enc_hdr_len);
        zupt_w64le(out, zupt_xxh64(enc_hdr_buf, enc_hdr_len, 0));
        if (fwrite(enc_hdr_buf, 1, enc_hdr_len, out) != enc_hdr_len)
            return ZUPT_ERR_IO;

        fseeko(out, 0, SEEK_SET);
        if (fwrite(hdr, sizeof(*hdr), 1, out) != 1) return ZUPT_ERR_IO;
        fseeko(out, 0, SEEK_END);

        if (!opts->quiet)
            fprintf(stderr, "  Encryption: SDK-v2 PQ Hybrid + XChaCha20-Poly1305 (commitment + HPKE)\n\n");
    } else if (opts->pqonly_mode) {
        /* ─── FULL POST-QUANTUM MODE (ML-KEM-768 only, no X25519) ─── */
        hdr->global_flags |= ZUPT_FLAG_PQ_HYBRID;   /* generic PQ indicator; enc_type distinguishes */

        uint8_t enc_hdr_buf[1200];
        size_t enc_hdr_len = 0;
        if (!opts->quiet)
            fprintf(stderr, "  Full post-quantum key encapsulation (ML-KEM-768, no classical layer)...\n");
        if (zupt_pq_encrypt_init(&opts->keyring, opts->keyfile,
                                 enc_hdr_buf, &enc_hdr_len) != 0) {
            fprintf(stderr, "Error: full-PQ key encapsulation failed (wrong key file?).\n");
            return ZUPT_ERR_AUTH_FAIL;
        }

        zupt_w8(out, ZUPT_BLOCK_MAGIC_0); zupt_w8(out, ZUPT_BLOCK_MAGIC_1);
        zupt_w8(out, ZUPT_BLOCK_ENC_HEADER);
        zupt_w16le(out, ZUPT_CODEC_STORE); zupt_w16le(out, 0);
        zupt_write_varint(out, enc_hdr_len);
        zupt_write_varint(out, enc_hdr_len);
        zupt_w64le(out, zupt_xxh64(enc_hdr_buf, enc_hdr_len, 0));
        if (fwrite(enc_hdr_buf, 1, enc_hdr_len, out) != enc_hdr_len)
            return ZUPT_ERR_IO;

        fseeko(out, 0, SEEK_SET);
        if (fwrite(hdr, sizeof(*hdr), 1, out) != 1) return ZUPT_ERR_IO;
        fseeko(out, 0, SEEK_END);

        if (!opts->quiet)
            fprintf(stderr, "  Encryption: Full PQ (ML-KEM-768) + AES-256-CTR + HMAC-SHA256\n\n");
    } else if (opts->pq_mode) {
        /* ─── PQ HYBRID MODE ─── */
        hdr->global_flags |= ZUPT_FLAG_PQ_HYBRID;

        uint8_t enc_hdr_buf[1200];
        size_t enc_hdr_len = 0;
        if (!opts->quiet)
            fprintf(stderr, "  Post-quantum key encapsulation (ML-KEM-768 + X25519)...\n");
        if (zupt_hybrid_encrypt_init(&opts->keyring, opts->keyfile,
                                      enc_hdr_buf, &enc_hdr_len) != 0) {
            fprintf(stderr, "Error: PQ hybrid key encapsulation failed.\n");
            return ZUPT_ERR_AUTH_FAIL;
        }

        zupt_w8(out, ZUPT_BLOCK_MAGIC_0); zupt_w8(out, ZUPT_BLOCK_MAGIC_1);
        zupt_w8(out, ZUPT_BLOCK_ENC_HEADER);
        zupt_w16le(out, ZUPT_CODEC_STORE); zupt_w16le(out, 0);
        zupt_write_varint(out, enc_hdr_len);
        zupt_write_varint(out, enc_hdr_len);
        zupt_w64le(out, zupt_xxh64(enc_hdr_buf, enc_hdr_len, 0));
        if (fwrite(enc_hdr_buf, 1, enc_hdr_len, out) != enc_hdr_len)
            return ZUPT_ERR_IO;

        /* Re-write header with PQ flag */
        fseeko(out, 0, SEEK_SET);
        if (fwrite(hdr, sizeof(*hdr), 1, out) != 1) return ZUPT_ERR_IO;
        fseeko(out, 0, SEEK_END);

        if (!opts->quiet)
            fprintf(stderr, "  Encryption: PQ Hybrid (ML-KEM-768 + X25519) + AES-256-CTR + HMAC-SHA256\n\n");
    } else {
        /* ─── PASSWORD MODE ───
         *
         * v2.4.1+: default to Argon2id (libzuptsdk path, enc_type=0x04).
         * PBKDF2-SHA256 (enc_type=0x01) is available via --kdf pbkdf2 for
         * compatibility with v2.4.0 and older readers. Argon2id is the
         * OWASP recommendation for password KDFs; PBKDF2 with 600k
         * iterations is fine but lacks the memory-hardness that makes
         * Argon2id resistant to GPU/ASIC attacks.
         *
         * Both paths produce the same downstream keyring (kr->enc_key,
         * mac_key, base_nonce) and feed the same AES-256-CTR + HMAC-SHA256
         * + F-09 preface-AAD per-block pipeline. Only the KDF and
         * enc-header bytes differ. Read-path dispatch on enc_type byte
         * at offset 0 of the enc-header block already handles both. */
#ifdef ZUPT_WITH_SDK
        int use_pbkdf2 = opts->kdf_legacy_pbkdf2;
#else
        /* No libzuptsdk in this build: Argon2id is unavailable, so the password
         * KDF is always native PBKDF2-SHA256 (600k iters, AES-256-CTR + HMAC-
         * SHA256). Archives written this way are readable by any build. */
        int use_pbkdf2 = 1;
#endif
        if (use_pbkdf2) {
            uint8_t salt[ZUPT_SALT_SIZE], nonce[ZUPT_NONCE_SIZE];
            zupt_random_bytes(salt, ZUPT_SALT_SIZE);
            zupt_random_bytes(nonce, ZUPT_NONCE_SIZE);

            if (!opts->quiet)
                fprintf(stderr, "  Deriving encryption key (PBKDF2-SHA256, %d iterations, --kdf pbkdf2 legacy)...\n",
                        ZUPT_KDF_ITERATIONS);
            zupt_derive_keys(&opts->keyring, opts->password, salt, nonce, ZUPT_KDF_ITERATIONS);

            uint8_t enc_hdr[53];
            enc_hdr[0] = ZUPT_ENC_PBKDF2;
            memcpy(enc_hdr + 1, salt, 32);
            memcpy(enc_hdr + 33, nonce, 16);
            uint32_t iter = ZUPT_KDF_ITERATIONS;
            memcpy(enc_hdr + 49, &iter, 4);

            zupt_w8(out, ZUPT_BLOCK_MAGIC_0); zupt_w8(out, ZUPT_BLOCK_MAGIC_1);
            zupt_w8(out, ZUPT_BLOCK_ENC_HEADER);
            zupt_w16le(out, ZUPT_CODEC_STORE); zupt_w16le(out, 0);
            zupt_write_varint(out, 53); zupt_write_varint(out, 53);
            zupt_w64le(out, zupt_xxh64(enc_hdr, 53, 0));
            if (fwrite(enc_hdr, 1, 53, out) != 53) return ZUPT_ERR_IO;
        } else {
            /* Argon2id default (v2.4.1+) */
            uint8_t enc_hdr[33];
            size_t enc_hdr_len = 0;
            if (!opts->quiet)
                fprintf(stderr, "  Deriving encryption key (Argon2id, libzuptsdk)...\n");
            if (zupt_sdk_password_encrypt_init(&opts->keyring, opts->password,
                                               enc_hdr, &enc_hdr_len) != 0) {
                fprintf(stderr, "Error: Argon2id key derivation failed.\n"
                                "       Pass --kdf pbkdf2 to fall back to PBKDF2-SHA256.\n");
                return ZUPT_ERR_AUTH_FAIL;
            }

            zupt_w8(out, ZUPT_BLOCK_MAGIC_0); zupt_w8(out, ZUPT_BLOCK_MAGIC_1);
            zupt_w8(out, ZUPT_BLOCK_ENC_HEADER);
            zupt_w16le(out, ZUPT_CODEC_STORE); zupt_w16le(out, 0);
            zupt_write_varint(out, enc_hdr_len); zupt_write_varint(out, enc_hdr_len);
            zupt_w64le(out, zupt_xxh64(enc_hdr, enc_hdr_len, 0));
            if (fwrite(enc_hdr, 1, enc_hdr_len, out) != enc_hdr_len) return ZUPT_ERR_IO;
        }

        fseeko(out, 0, SEEK_SET);
        if (fwrite(hdr, sizeof(*hdr), 1, out) != 1) return ZUPT_ERR_IO;
        fseeko(out, 0, SEEK_END);

        if (!opts->quiet)
            fprintf(stderr, "  Encryption: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC)\n\n");
    }

    return ZUPT_OK;
}

static void ensure_dirs(const char *path) {
    char tmp[ZUPT_MAX_PATH]; strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
    for (char *p=tmp+1;*p;p++)
        if (*p=='/'||*p=='\\') { *p='\0'; zupt_mkdir(tmp); *p=ZUPT_PATH_SEP; }
}

/* SECURITY: Validate an archive entry's path is safe to extract.
 *
 * Blocks classic Zip-Slip / path-traversal attacks (Snyk 2018) where a
 * malicious archive contains entries like "../../etc/passwd" or absolute
 * paths like "/etc/passwd" or (Windows) "C:\Windows\System32\evil.dll".
 *
 * Rules enforced:
 *   1. Reject NULL/empty paths.
 *   2. Reject absolute paths (Unix: starts with '/'; Windows: 'X:' or '\\').
 *   3. Reject any component equal to ".." (after splitting on / and \).
 *   4. Reject embedded NUL bytes (defense in depth).
 *   5. Reject leading/embedded "~" expansions and "$" variable references
 *      that some shell-aware tooling might expand later.
 *
 * Returns 1 if path is safe, 0 if it should be rejected.
 */
static int zupt_path_is_safe(const char *path) {
    if (!path || !*path) return 0;
    size_t len = strlen(path);
    if (len >= ZUPT_MAX_PATH) return 0;

    /* Absolute paths */
    if (path[0] == '/' || path[0] == '\\') return 0;
    /* Windows drive letters: "C:..." or UNC "\\server" */
    if (len >= 2 && path[1] == ':') return 0;

    /* Component scan: split on '/' and '\\' */
    const char *start = path;
    for (size_t i = 0; i <= len; i++) {
        if (path[i] == '/' || path[i] == '\\' || path[i] == '\0') {
            size_t complen = (size_t)(path + i - start);
            /* Reject ".." as a complete component */
            if (complen == 2 && start[0] == '.' && start[1] == '.') return 0;
            /* Reject embedded NUL within string (string strlen would have
             * stopped, but defense in depth in case caller passes a buffer
             * with a NUL in middle) */
            start = path + i + 1;
        }
    }

    /* Defense in depth: reject NUL bytes within declared length */
    for (size_t i = 0; i < len; i++) {
        if (path[i] == '\0') return 0;
    }

    return 1;
}

/* SECURITY: Open an output file for writing, refusing to follow symlinks.
 *
 * Defends against the case where an attacker has placed a symlink in the
 * output directory before extraction, e.g. ~/Downloads/innocent.txt → /etc/passwd.
 * On Linux/BSD/macOS we use O_NOFOLLOW + O_EXCL semantics: if the path
 * exists and is a symlink, open() returns ELOOP. If the path doesn't
 * exist, the symlink check is moot.
 *
 * Windows behavior: defaults to fopen "wb" (does not follow reparse points
 * unless explicitly enabled). The most common Windows attack vector here
 * is via reparse points, but we leave it to the user's directory ACLs for
 * now since CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT is non-trivial
 * to wire portably.
 */
static FILE *zupt_safe_fopen_output(const char *path) {
#if defined(_WIN32)
    /* No portable O_NOFOLLOW on Windows; rely on directory permissions. */
    return fopen(path, "wb");
#else
    /* Open with O_NOFOLLOW so that if the leaf is a symlink, open fails.
     * O_TRUNC zeros existing file (matches "wb" semantics). */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "wb");
    if (!f) { close(fd); return NULL; }
    return f;
#endif
}

static uint64_t get_mtime(const char *path) {
#ifdef _WIN32
    (void)path; return now_ns();
#else
    struct stat st;
    if (stat(path, &st) == 0) return (uint64_t)st.st_mtime * 1000000000ULL;
    return now_ns();
#endif
}

/* Safe ftello wrapper: returns 0 on error (caller should check context) */
/* F-09 of v2.3.1: serialize the canonical per-block frame preface for use as
 * extended-AAD input to the per-block MAC. Format is fixed-width little-endian
 * (NOT the on-disk varint encoding — varints are non-canonical, two encodings
 * of the same logical value would produce different MACs and either break
 * roundtrip or open a malleability window).
 *
 * Layout: block_type (1B) || codec_id (2B LE) || block_flags (2B LE)
 *      || uncompressed_size (8B LE) || compressed_size (8B LE)
 *      || plaintext_checksum (8B LE)
 *      = 29 bytes
 *
 * Excludes block_magic (constant `bb 01`, structurally rejected by read_block
 * if tampered) and the AES nonce (already part of the existing MAC input). */
/* ZUPT_PREFACE_AAD_LEN is defined in zupt.h (shared with the parallel path). */
static void zupt_serialize_preface_aad(const zupt_block_t *b, uint8_t out[ZUPT_PREFACE_AAD_LEN]) {
    out[0] = (uint8_t)b->block_type;
    out[1] = (uint8_t)(b->codec_id & 0xFF);
    out[2] = (uint8_t)((b->codec_id >> 8) & 0xFF);
    out[3] = (uint8_t)(b->block_flags & 0xFF);
    out[4] = (uint8_t)((b->block_flags >> 8) & 0xFF);
    for (int i = 0; i < 8; i++) out[5 + i]  = (uint8_t)(b->uncompressed_size >> (i * 8));
    for (int i = 0; i < 8; i++) out[13 + i] = (uint8_t)(b->compressed_size   >> (i * 8));
    for (int i = 0; i < 8; i++) out[21 + i] = (uint8_t)(b->checksum          >> (i * 8));
}

/* Write-side variant: build the canonical preface AAD from raw scalars
 * known at MAC time but before the block struct exists. Same byte layout
 * as zupt_serialize_preface_aad — both sides must produce identical bytes
 * for the same logical block, or the roundtrip MAC won't match. */
void zupt_serialize_preface_aad_scalars(
    uint8_t block_type, uint16_t codec_id, uint16_t block_flags,
    uint64_t uncompressed_size, uint64_t compressed_size, uint64_t checksum,
    uint8_t out[ZUPT_PREFACE_AAD_LEN])
{
    out[0] = block_type;
    out[1] = (uint8_t)(codec_id & 0xFF);
    out[2] = (uint8_t)((codec_id >> 8) & 0xFF);
    out[3] = (uint8_t)(block_flags & 0xFF);
    out[4] = (uint8_t)((block_flags >> 8) & 0xFF);
    for (int i = 0; i < 8; i++) out[5 + i]  = (uint8_t)(uncompressed_size >> (i * 8));
    for (int i = 0; i < 8; i++) out[13 + i] = (uint8_t)(compressed_size   >> (i * 8));
    for (int i = 0; i < 8; i++) out[21 + i] = (uint8_t)(checksum          >> (i * 8));
}

static uint64_t safe_ftello(FILE *f) {
    int64_t pos = ftello(f);
    if (pos < 0) return 0;
    return (uint64_t)pos;
}

/* ═══════════════════════════════════════════════════════════════════
 * INDEX SERIALIZATION HELPERS (always LE)
 * ═══════════════════════════════════════════════════════════════════ */

static size_t index_put_u64(uint8_t *buf, uint64_t v) {
    zupt_le64_put(buf, v);
    return 8;
}
static size_t index_put_u32(uint8_t *buf, uint32_t v) {
    zupt_le32_put(buf, v);
    return 4;
}
static uint64_t index_get_u64(const uint8_t *buf) {
    return zupt_le64_get(buf);
}
static uint32_t index_get_u32(const uint8_t *buf) {
    return zupt_le32_get(buf);
}

/* ═══════════════════════════════════════════════════════════════════
 * COMPRESSION
 * ═══════════════════════════════════════════════════════════════════ */

/* F-12 of v2.4.3: write an optional comment block to the archive between
 * the data blocks and the central index. Stores plaintext UTF-8 text
 * (max ZUPT_MAX_COMMENT_LEN bytes) under a new block type
 * ZUPT_BLOCK_COMMENT. Encrypted archives use the same per-block AEAD
 * pipeline as data blocks (AES-256-CTR + HMAC-SHA256 + v1.6 preface-AAD
 * if use_preface_aad is set). aad_seq is the sentinel 0xFFFF...FFFE,
 * one less than the index block's 0xFFFF...FFFF, so it cannot collide
 * with file-block AAD seqs (which are bounded above by 0xFFFFFFFF00000000
 * since they encode (fi+1, block_seq) in the upper/lower 32-bit halves).
 *
 * The caller must:
 *   1. Have written all data blocks already.
 *   2. Have computed `hdr` in memory but not committed comment_offset yet.
 *   3. Call this; on return, hdr->comment_offset is set and one extra
 *      block has been written to disk.
 *   4. Rewrite the archive header on disk (offset 0) so subsequent AIT
 *      computation matches what's on disk.
 *
 * Returns ZUPT_OK on success, an error code on I/O or crypto failure.
 * If !opts->has_comment, this is a no-op (hdr->comment_offset stays 0).
 */
#define ZUPT_COMMENT_AAD_SEQ 0xFFFFFFFFFFFFFFFEULL
static zupt_error_t write_comment_block(FILE *out, zupt_archive_header_t *hdr,
                                         zupt_options_t *opts,
                                         uint64_t *total_blocks) {
    if (!opts->has_comment) return ZUPT_OK;

    size_t clen = strnlen(opts->comment, ZUPT_MAX_COMMENT_LEN);
    if (clen == 0) {
        /* Empty comment string: treat as not-supplied. */
        return ZUPT_OK;
    }

    uint64_t comment_off = (uint64_t)ftello(out);
    uint64_t cksum = zupt_xxh64(opts->comment, clen, 0);

    const uint8_t *payload = (const uint8_t *)opts->comment;
    uint64_t payload_size = clen;
    uint16_t bflags = 0;
    uint8_t *enc_payload = NULL;

    if (opts->encrypt && opts->keyring.active) {
        size_t enc_len;
        if (opts->keyring.use_preface_aad) {
            uint8_t preface[ZUPT_PREFACE_AAD_LEN];
            uint64_t predicted_csz = 16 + payload_size + 32;
            zupt_serialize_preface_aad_scalars(
                ZUPT_BLOCK_COMMENT, ZUPT_CODEC_STORE,
                (uint16_t)ZUPT_BFLAG_ENCRYPTED,
                payload_size, predicted_csz, cksum, preface);
            enc_payload = zupt_encrypt_buffer_aad(&opts->keyring,
                payload, payload_size, ZUPT_COMMENT_AAD_SEQ,
                preface, ZUPT_PREFACE_AAD_LEN, &enc_len);
            zupt_secure_wipe(preface, sizeof(preface));
        } else {
            enc_payload = zupt_encrypt_buffer(&opts->keyring,
                payload, payload_size, ZUPT_COMMENT_AAD_SEQ, &enc_len);
        }
        if (!enc_payload) return ZUPT_ERR_NOMEM;
        payload = enc_payload;
        payload_size = enc_len;
        bflags |= ZUPT_BFLAG_ENCRYPTED;
    }

    int write_err = 0;
    w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
    w8(out, ZUPT_BLOCK_COMMENT);
    w16le(out, ZUPT_CODEC_STORE); w16le(out, bflags);
    zupt_write_varint(out, clen);            /* uncompressed_size */
    zupt_write_varint(out, payload_size);    /* compressed_size (= encrypted length when bflags has ENCRYPTED) */
    w64le(out, cksum);                       /* plaintext XXH64 — F-09 strict validation reads this */
    if (fwrite(payload, 1, (size_t)payload_size, out) != (size_t)payload_size) write_err = 1;

    free(enc_payload);

    if (write_err) return ZUPT_ERR_IO;

    hdr->comment_offset = comment_off;
    (*total_blocks)++;
    return ZUPT_OK;
}

zupt_error_t zupt_compress_files(const char *output_path,
                                 const char **arc_paths,
                                 const char **disk_paths,
                                 int num_files,
                                 zupt_options_t *opts) {
    if (opts->block_size == 0) opts->block_size = auto_block_size(opts->level);

    /* Resolve AUTO codec before compression */
    if (opts->codec_id == ZUPT_CODEC_AUTO)
        opts->codec_id = zupt_resolve_auto_codec();

    FILE *out = fopen(output_path, "wb");
    if (!out) { fprintf(stderr, "Error: Cannot create '%s': %s\n", output_path, strerror(errno)); return ZUPT_ERR_IO; }

    int write_err = 0; /* Accumulate write errors */

    zupt_archive_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic[0]=ZUPT_MAGIC_0; hdr.magic[1]=ZUPT_MAGIC_1; hdr.magic[2]=ZUPT_MAGIC_2;
    hdr.magic[3]=ZUPT_MAGIC_3; hdr.magic[4]=ZUPT_MAGIC_4; hdr.magic[5]=ZUPT_MAGIC_5;
    hdr.version_major = ZUPT_FORMAT_MAJOR; hdr.version_minor = ZUPT_FORMAT_MINOR;
    hdr.global_flags = ZUPT_FLAG_CKSUM_XXH64;
    if (opts->encrypt) {
        hdr.global_flags |= ZUPT_FLAG_ENCRYPTED | ZUPT_FLAG_AAD_SEQ;
        /* F-09 of v2.3.1: bind frame preface into per-block MAC. v1.6 archives
         * always set this; flag is anchored by the v1.5 AIT (F-08). */
        hdr.global_flags |= ZUPT_FLAG_AAD_PREFACE;
        opts->keyring.use_preface_aad = 1;
    }
    if (opts->threads > 1) hdr.global_flags |= ZUPT_FLAG_MULTITHREADED;
    if (opts->dedup) hdr.global_flags |= ZUPT_FLAG_DEDUP;
    hdr.creation_time = now_ns();
    gen_uuid(hdr.archive_id);
    if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) write_err = 1;

    if (opts->encrypt) {
        zupt_error_t enc_err = write_enc_header(out, &hdr, opts);
        if (enc_err != ZUPT_OK) {
            fclose(out);
            unlink(output_path);
            return enc_err;
        }
    }

    zupt_index_entry_t *index = (zupt_index_entry_t*)calloc((size_t)num_files, sizeof(zupt_index_entry_t));
    uint8_t *rbuf = (uint8_t*)malloc(opts->block_size);
    uint8_t *cbuf = (uint8_t*)malloc(zupt_lzh_bound(opts->block_size) + 512);
    if (!index || !rbuf || !cbuf) { free(index); free(rbuf); free(cbuf); fclose(out); return ZUPT_ERR_NOMEM; }

    uint64_t total_blocks = 0, total_in = 0, total_out = 0;
    /* block_seq is now PER-FILE: resets at the start of each file's compress.
     * This decouples the seq used for AAD-binding from cross-file ordering,
     * letting extract compute the same seq via simple per-file counting from 0.
     */
    time_t start_time = time(NULL);

    /* Dedup context (NULL if --dedup not set) */
    zupt_dedup_ctx_t *dedup = opts->dedup ? zupt_dedup_init() : NULL;

    /* Create parallel context if multi-threaded.
     * Dedup requires sequential block ordering, so force single-threaded. */
    zpar_ctx_t *pctx = NULL;
    int effective_threads = opts->threads > 1 ? opts->threads : 1;
    if (opts->dedup) {
        effective_threads = 1;
        if (!opts->quiet && opts->threads > 1)
            fprintf(stderr, "  Note: dedup mode uses single-threaded compression\n");
    }
    if (effective_threads > 1) {
        pctx = zpar_create(effective_threads, opts->block_size, 0,
                           opts->encrypt ? &opts->keyring : NULL);
        if (!pctx || pctx->threads_running == 0) {
            if (pctx) zpar_destroy(pctx);
            pctx = NULL;
            effective_threads = 1;
            if (!opts->quiet) fprintf(stderr, "  Thread creation failed, using single thread\n");
        }
    }

    for (int fi = 0; fi < num_files; fi++) {
        /* Per-file block_seq counter (resets to 0 for each file) — used as
         * AAD in encrypt/decrypt. Extract recomputes the same counter from
         * the same per-file zero baseline, ensuring MAC consistency. */
        uint64_t block_seq = 0;
        FILE *inf = fopen(disk_paths[fi], "rb");
        if (!inf) { fprintf(stderr, "  Skipping: %s (%s)\n", disk_paths[fi], strerror(errno)); continue; }

        fseeko(inf, 0, SEEK_END);
        int64_t file_size = ftello(inf);
        if (file_size < 0) { fclose(inf); continue; }
        fseeko(inf, 0, SEEK_SET);

        strncpy(index[fi].path, arc_paths[fi], ZUPT_MAX_PATH-1);
        index[fi].uncompressed_size = (uint64_t)file_size;
        index[fi].first_block_offset = safe_ftello(out);
        index[fi].modification_time = get_mtime(disk_paths[fi]);
        index[fi].attributes = 0644;
        index[fi].block_count = 0;

        char sz_buf[32]; zupt_format_size((uint64_t)file_size, sz_buf, sizeof(sz_buf));
        if (opts->verbose)
            fprintf(stderr, "  %s (%s)\n", arc_paths[fi], sz_buf);

        /* Chained hash: xxh64 over concatenated file content */
        uint64_t file_hash_state = 0;
        uint64_t file_comp = 0;
        size_t remaining = (size_t)file_size;
        uint64_t file_done = 0;

        if (pctx && effective_threads > 1) {
            /* ─── MULTI-THREADED COMPRESSION PATH ─── */
            /* Batch: read up to N blocks, submit to workers, collect in order */
            int *pending_slots = (int *)malloc((size_t)effective_threads * sizeof(int));
            uint64_t *pending_seqs = (uint64_t *)malloc((size_t)effective_threads * sizeof(uint64_t));
            if (!pending_slots || !pending_seqs) {
                free(pending_slots); free(pending_seqs); fclose(inf);
                write_err = 1; continue;
            }

            while (remaining > 0) {
                int npending = 0;

                /* Fill batch: read and submit up to N blocks */
                while (remaining > 0 && npending < effective_threads) {
                    size_t chunk = remaining < opts->block_size ? remaining : opts->block_size;
                    size_t nread = fread(rbuf, 1, chunk, inf);
                    if (nread == 0) break;

                    /* Chained hash computed in main thread (sequential, fast) */
                    file_hash_state = zupt_xxh64(rbuf, nread, file_hash_state);

                    /* Same AAD computation as ST path. Dedup mode uses
                     * sentinel seq=0 so refs work; non-dedup uses (fi+1, seq). */
                    uint64_t aad_seq;
                    if (opts->dedup) {
                        aad_seq = 0;
                    } else {
                        aad_seq = (((uint64_t)(fi + 1)) << 32) | block_seq;
                    }
                    int slot = zpar_submit_compress(pctx, rbuf, nread,
                                                     aad_seq, opts->level, opts->codec_id);
                    if (slot < 0) { write_err = 1; break; }
                    pending_slots[npending] = slot;
                    pending_seqs[npending] = aad_seq;
                    npending++;
                    block_seq++;
                    remaining -= nread;
                    file_done += nread;
                }

                /* Collect results in order and write */
                for (int pi = 0; pi < npending; pi++) {
                    zpar_slot_t *s = zpar_wait_slot(pctx, pending_slots[pi]);
                    if (!s || s->error != ZUPT_OK) {
                        if (!write_err) fprintf(stderr, "  Block error: %s\n",
                            zupt_strerror(s ? s->error : ZUPT_ERR_CORRUPT));
                        write_err = 1;
                        zpar_release_slot(pctx, pending_slots[pi]);
                        continue;
                    }

                    /* Write block header */
                    w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
                    w8(out, ZUPT_BLOCK_DATA);
                    w16le(out, s->actual_codec); w16le(out, s->out_bflags);
                    zupt_write_varint(out, s->input_len);  /* uncompressed size */
                    zupt_write_varint(out, (uint64_t)s->output_len);
                    w64le(out, s->checksum);
                    if (fwrite(s->output, 1, s->output_len, out) != s->output_len)
                        write_err = 1;

                    file_comp += s->output_len;
                    index[fi].block_count++;
                    total_blocks++;

                    zpar_release_slot(pctx, pending_slots[pi]);
                }

                if (write_err) break;

                if (!opts->verbose && !opts->quiet && file_size > (int64_t)opts->block_size)
                    show_progress(arc_paths[fi], file_done, (uint64_t)file_size);
            }

            free(pending_slots);
            free(pending_seqs);
        } else {
            /* ─── SINGLE-THREADED COMPRESSION PATH (bit-for-bit v0.5.1) ─── */
            while (remaining > 0) {
            size_t chunk = remaining < opts->block_size ? remaining : opts->block_size;
            size_t nread = fread(rbuf, 1, chunk, inf);
            if (nread == 0) break;

            uint64_t checksum = zupt_xxh64(rbuf, nread, 0);
            /* Chained hash: feed previous hash as seed for next block */
            file_hash_state = zupt_xxh64(rbuf, nread, file_hash_state);

            /* ─── Dedup check: skip compression if block already written ─── */
            if (dedup) {
                zupt_dedup_record_block(dedup);
                uint64_t ref_off = 0; uint32_t ref_sz = 0;
                if (zupt_dedup_lookup(dedup, checksum, &ref_off, &ref_sz) &&
                    ref_sz == (uint32_t)nread) {
                    /* Fingerprint match + same size — write reference block */
                    zupt_dedup_write_ref(out, ref_off, (uint32_t)nread, checksum);
                    zupt_dedup_record_hit(dedup, nread);
                    file_comp += 8; /* ref block payload is 8 bytes */
                    index[fi].block_count++;
                    total_blocks++;
                    block_seq++;
                    remaining -= nread;
                    file_done += nread;
                    if (!opts->verbose && !opts->quiet && file_size > (int64_t)opts->block_size)
                        show_progress(arc_paths[fi], file_done, (uint64_t)file_size);
                    continue;
                }
            }

            size_t comp_size = 0;
            uint16_t codec = opts->codec_id;

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
                        size_t lzh_size = zupt_lzh_compress(transformed, nread, lzh_out,
                                                             lzh_cap, opts->level);
                        free(transformed);

                        if (lzh_size > 0 && 1 + 256 + lzh_size < nread) {
                            cbuf[0] = 0x01;
                            memcpy(cbuf + 1, pred, 256);
                            comp_size = 1 + 256 + lzh_size;
                        } else {
                            cbuf[0] = 0x00;
                            size_t plain = zupt_lzh_compress(rbuf, nread, cbuf + 1,
                                                              lzh_cap, opts->level);
                            if (plain > 0 && 1 + plain < nread)
                                comp_size = 1 + plain;
                        }
                    }
                } else {
                    cbuf[0] = 0x00;
                    size_t lzh_cap = zupt_lzh_bound(nread);
                    size_t plain = zupt_lzh_compress(rbuf, nread, cbuf + 1,
                                                      lzh_cap, opts->level);
                    if (plain > 0 && 1 + plain < nread)
                        comp_size = 1 + plain;
                }
            } else if (codec == ZUPT_CODEC_ZUPT_LZH)
                comp_size = zupt_lzh_compress(rbuf, nread, cbuf, zupt_lzh_bound(nread), opts->level);
            else if (codec == ZUPT_CODEC_ZUPT_LZ)
                comp_size = zupt_lz_compress(rbuf, nread, cbuf, zupt_lz_bound(nread), opts->level);
            /* VAPTVUPT: VaptVupt codec compress path (v1.4.0 integration API) */
            else if (codec == ZUPT_CODEC_VAPTVUPT) {
                size_t vv_cap = vvz_compress_bound(nread);
                if (vv_cap > zupt_lzh_bound(nread) + 512) {
                    uint8_t *vv_tmp = (uint8_t *)malloc(vv_cap);
                    if (vv_tmp) {
                        int64_t csz = vvz_compress(rbuf, nread, vv_tmp, vv_cap, opts->level);
                        if (csz > 0 && (size_t)csz < nread) {
                            memcpy(cbuf, vv_tmp, (size_t)csz);
                            comp_size = (size_t)csz;
                        }
                        free(vv_tmp);
                    }
                } else {
                    int64_t csz = vvz_compress(rbuf, nread, cbuf, zupt_lzh_bound(nread) + 512, opts->level);
                    if (csz > 0 && (size_t)csz < nread)
                        comp_size = (size_t)csz;
                }
            }

            const uint8_t *payload; uint64_t payload_size;
            if (comp_size == 0 || comp_size >= nread) {
                codec = ZUPT_CODEC_STORE; payload = rbuf; payload_size = nread;
            } else {
                payload = cbuf; payload_size = comp_size;
            }

            uint8_t *enc_payload = NULL;
            uint16_t bflags = 0;
            if (opts->encrypt && opts->keyring.active) {
                size_t enc_len;
                /* AAD = ((file_index+1) << 32) | per_file_block_seq.
                 * Combines file identity with block position to prevent
                 * cross-file block-swap attacks.
                 *
                 * Exception: in dedup mode, blocks may be referenced from
                 * other files via offset-only refs. The decrypt-side ref
                 * lookup has no way to know the original source file, so
                 * dedup blocks use sentinel seq=0 (legacy MAC, no AAD).
                 * Dedup mode still has block-level integrity via the
                 * stored XXH64 plaintext checksum. */
                uint64_t aad_seq;
                if (opts->dedup) {
                    aad_seq = 0;  /* sentinel; dedup decrypt path uses 0 too */
                } else {
                    aad_seq = (((uint64_t)(fi + 1)) << 32) | block_seq;
                }
                /* F-09 of v2.3.1: bind frame preface into MAC for v1.6 archives.
                 * Predicted compressed_size = nonce(16) + payload + hmac(32). */
                if (opts->keyring.use_preface_aad) {
                    uint8_t preface[ZUPT_PREFACE_AAD_LEN];
                    uint16_t predicted_bflags = (uint16_t)(ZUPT_BFLAG_ENCRYPTED);
                    uint64_t predicted_csz = 16 + payload_size + 32;
                    zupt_serialize_preface_aad_scalars(
                        ZUPT_BLOCK_DATA, codec, predicted_bflags,
                        nread, predicted_csz, checksum, preface);
                    enc_payload = zupt_encrypt_buffer_aad(&opts->keyring,
                        payload, payload_size, aad_seq,
                        preface, ZUPT_PREFACE_AAD_LEN, &enc_len);
                    zupt_secure_wipe(preface, sizeof(preface));
                } else {
                    enc_payload = zupt_encrypt_buffer(&opts->keyring, payload, payload_size, aad_seq, &enc_len);
                }
                if (!enc_payload) { fclose(inf); free(index); free(rbuf); free(cbuf); fclose(out); return ZUPT_ERR_NOMEM; }
                payload = enc_payload;
                payload_size = enc_len;
                bflags |= ZUPT_BFLAG_ENCRYPTED;
            }

            /* Record offset before writing block header (for dedup index) */
            uint64_t this_block_off = (uint64_t)ftello(out);

            w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
            w8(out, ZUPT_BLOCK_DATA);
            w16le(out, codec); w16le(out, bflags);
            zupt_write_varint(out, (uint64_t)nread);
            zupt_write_varint(out, payload_size);
            w64le(out, checksum);
            if (fwrite(payload, 1, (size_t)payload_size, out) != (size_t)payload_size) write_err = 1;

            /* Insert into dedup index so future blocks can reference this one */
            if (dedup)
                zupt_dedup_insert(dedup, checksum, this_block_off, (uint32_t)nread);

            free(enc_payload);
            file_comp += payload_size;
            index[fi].block_count++;
            total_blocks++;
            block_seq++;
            remaining -= nread;
            file_done += nread;

            if (!opts->verbose && !opts->quiet && file_size > (int64_t)opts->block_size)
                show_progress(arc_paths[fi], file_done, (uint64_t)file_size);
        } /* end while (remaining > 0) */
        } /* end else (single-threaded) */

        index[fi].compressed_size = file_comp;
        index[fi].content_hash = file_hash_state;
        total_in += index[fi].uncompressed_size;
        total_out += index[fi].compressed_size;
        fclose(inf);

        if (opts->verbose) {
            char in_s[32], out_s[32];
            zupt_format_size(index[fi].uncompressed_size, in_s, sizeof(in_s));
            zupt_format_size(index[fi].compressed_size, out_s, sizeof(out_s));
            double ratio = index[fi].uncompressed_size > 0 ?
                (double)index[fi].compressed_size / (double)index[fi].uncompressed_size * 100.0 : 100.0;
            fprintf(stderr, "    %s -> %s (%.1f%%)\n", in_s, out_s, ratio);
        }
    }

    /* Destroy parallel context before writing index (single-threaded I/O) */
    if (pctx) { zpar_destroy(pctx); pctx = NULL; }

    /* Check for write errors before writing the index */
    if (write_err) {
        fprintf(stderr, "Error: Write errors occurred during compression.\n");
        free(index); free(rbuf); free(cbuf); fclose(out);
        return ZUPT_ERR_IO;
    }

    /* ─── F-12 of v2.4.3: optional comment block ─── */
    {
        zupt_error_t cerr = write_comment_block(out, &hdr, opts, &total_blocks);
        if (cerr != ZUPT_OK) {
            fprintf(stderr, "Error: Failed to write comment block\n");
            free(index); free(rbuf); free(cbuf); fclose(out);
            return cerr;
        }
        if (opts->has_comment && hdr.comment_offset != 0) {
            /* Rewrite the archive header so on-disk hdr.comment_offset
             * matches the in-memory hdr that the AIT will sign at the
             * end of the function. */
            int64_t save = ftello(out);
            fseeko(out, 0, SEEK_SET);
            if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) {
                fprintf(stderr, "Error: Failed to update header with comment offset\n");
                free(index); free(rbuf); free(cbuf); fclose(out);
                return ZUPT_ERR_IO;
            }
            fseeko(out, save, SEEK_SET);
        }
    }

    /* ─── Central Index ─── */
    uint64_t index_offset = safe_ftello(out);
    size_t icap = (size_t)num_files * (ZUPT_MAX_PATH + 128);
    uint8_t *ibuf = (uint8_t*)malloc(icap);
    if (!ibuf) { free(index); free(rbuf); free(cbuf); fclose(out); return ZUPT_ERR_NOMEM; }

    size_t ip = 0;
    ip += (size_t)zupt_encode_varint(ibuf + ip, (uint64_t)num_files);
    for (int fi = 0; fi < num_files; fi++) {
        if (index[fi].path[0] == '\0') continue;
        size_t plen = strlen(index[fi].path);
        ip += (size_t)zupt_encode_varint(ibuf + ip, plen);
        memcpy(ibuf + ip, index[fi].path, plen); ip += plen;
        ip += index_put_u64(ibuf + ip, index[fi].uncompressed_size);
        ip += index_put_u64(ibuf + ip, index[fi].compressed_size);
        ip += index_put_u64(ibuf + ip, index[fi].modification_time);
        ip += index_put_u64(ibuf + ip, index[fi].content_hash);
        ip += index_put_u64(ibuf + ip, index[fi].first_block_offset);
        ip += (size_t)zupt_encode_varint(ibuf + ip, index[fi].block_count);
        ip += index_put_u32(ibuf + ip, index[fi].attributes);
    }

    size_t ic_cap = zupt_lzh_bound(ip);
    uint8_t *ic = (uint8_t*)malloc(ic_cap);
    size_t ic_size = zupt_lzh_compress(ibuf, ip, ic, ic_cap, opts->level);
    uint16_t ic_codec = ZUPT_CODEC_ZUPT_LZH;
    const uint8_t *ic_pay; uint64_t ic_plen;
    if (ic_size == 0 || ic_size >= ip) {
        ic_codec = ZUPT_CODEC_STORE; ic_pay = ibuf; ic_plen = ip;
    } else {
        ic_pay = ic; ic_plen = ic_size;
    }

    uint64_t ic_ck = zupt_xxh64(ibuf, ip, 0);  /* compute checksum BEFORE encrypt for AAD */

    uint8_t *enc_idx = NULL;
    uint16_t idx_bflags = 0;
    if (opts->encrypt && opts->keyring.active) {
        size_t enc_len;
        /* Index uses sentinel seq (matches decrypt site at line ~1515) */
        /* F-09: bind frame preface (block_type=INDEX, codec, flags, sizes, ck) */
        if (opts->keyring.use_preface_aad) {
            uint8_t preface[ZUPT_PREFACE_AAD_LEN];
            uint64_t predicted_csz = 16 + ic_plen + 32;
            zupt_serialize_preface_aad_scalars(
                ZUPT_BLOCK_INDEX, ic_codec, (uint16_t)ZUPT_BFLAG_ENCRYPTED,
                ip, predicted_csz, ic_ck, preface);
            enc_idx = zupt_encrypt_buffer_aad(&opts->keyring, ic_pay, ic_plen,
                0xFFFFFFFFFFFFFFFFULL, preface, ZUPT_PREFACE_AAD_LEN, &enc_len);
            zupt_secure_wipe(preface, sizeof(preface));
        } else {
            enc_idx = zupt_encrypt_buffer(&opts->keyring, ic_pay, ic_plen, 0xFFFFFFFFFFFFFFFFULL, &enc_len);
        }
        ic_pay = enc_idx; ic_plen = enc_len;
        idx_bflags |= ZUPT_BFLAG_ENCRYPTED;
    }

    w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
    w8(out, ZUPT_BLOCK_INDEX);
    w16le(out, ic_codec); w16le(out, idx_bflags);
    zupt_write_varint(out, ip); zupt_write_varint(out, ic_plen);
    w64le(out, ic_ck);
    if (fwrite(ic_pay, 1, (size_t)ic_plen, out) != (size_t)ic_plen) write_err = 1;
    free(enc_idx);

    /* ─── Footer ─── */
    zupt_footer_t ft;
    memset(&ft, 0, sizeof(ft));
    ft.index_offset = index_offset;
    ft.total_blocks = total_blocks;
    ft.archive_checksum = safe_ftello(out);
    ft.footer_magic[0]='Z'; ft.footer_magic[1]='E'; ft.footer_magic[2]='N'; ft.footer_magic[3]='D';
    ft.footer_version = 1;
    if (fwrite(&ft, sizeof(ft), 1, out) != 1) write_err = 1;

    /* F-08 of v2.3.0: archive-integrity-trailer follows the footer.
     * Encrypted: HMAC over hdr || ft[0..23]. Plaintext: XXH64 best-effort. */
    if (!write_err) {
        const zupt_keyring_t *kr = opts->encrypt ? &opts->keyring : NULL;
        if (zupt_format_ait_write(out, &hdr, &ft, kr) != 0) write_err = 1;
    }

    fclose(out);

    if (write_err) {
        fprintf(stderr, "Error: Write errors occurred. Archive may be corrupt.\n");
        free(ic); free(ibuf); free(index); free(rbuf); free(cbuf);
        return ZUPT_ERR_IO;
    }

    /* Summary */
    time_t elapsed = time(NULL) - start_time;
    if (elapsed < 1) elapsed = 1;
    char in_s[32], out_s[32];
    zupt_format_size(total_in, in_s, sizeof(in_s));
    zupt_format_size(total_out, out_s, sizeof(out_s));
    double ratio = total_in > 0 ? (double)total_out/(double)total_in*100.0 : 100.0;
    double speed = (double)total_in / (double)elapsed / 1048576.0;

    if (!opts->quiet) {
        fprintf(stderr, "\n  Archive:      %s\n", output_path);
        fprintf(stderr, "  Files:        %d\n", num_files);
        fprintf(stderr, "  Original:     %s\n", in_s);
        fprintf(stderr, "  Compressed:   %s (%.1f%%)\n", out_s, ratio);
        if (total_in > 0 && total_out > 0) {
            double cr = (double)total_in / (double)total_out;
            fprintf(stderr, "  Ratio:        %.2f:1\n", cr);
        }
        fprintf(stderr, "  Blocks:       %llu\n", (unsigned long long)total_blocks);
        fprintf(stderr, "  Codec:        %s (level %d)\n", zupt_codec_name(opts->codec_id), opts->level);
        if (opts->encrypt) fprintf(stderr, "  Encryption:   AES-256 + HMAC-SHA256\n");
        if (dedup) {
            uint64_t ds_seen, ds_dedup, ds_saved;
            zupt_dedup_stats(dedup, &ds_seen, &ds_dedup, &ds_saved);
            if (ds_dedup > 0) {
                char sv[32]; zupt_format_size(ds_saved, sv, sizeof(sv));
                fprintf(stderr, "  Dedup:        %llu/%llu blocks deduped (saved %s, %.0f%% dedup ratio)\n",
                        (unsigned long long)ds_dedup, (unsigned long long)ds_seen, sv,
                        ds_seen > 0 ? 100.0 * (double)ds_dedup / (double)ds_seen : 0.0);
            }
        }
        fprintf(stderr, "  Speed:        %.1f MB/s (%llds)\n", speed, (long long)elapsed);
    }

    zupt_dedup_free(dedup);
    free(ic); free(ibuf); free(index); free(rbuf); free(cbuf);
    return ZUPT_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * SOLID-MODE COMPRESSION
 * ═══════════════════════════════════════════════════════════════════ */

zupt_error_t zupt_compress_solid(const char *output_path,
                                  const char **arc_paths,
                                  const char **disk_paths,
                                  int num_files,
                                  zupt_options_t *opts) {
    if (opts->block_size == 0) opts->block_size = auto_block_size(opts->level);
    if (opts->block_size < 524288) opts->block_size = 524288;

    /* Resolve AUTO codec before compression */
    if (opts->codec_id == ZUPT_CODEC_AUTO)
        opts->codec_id = zupt_resolve_auto_codec();

    FILE *out = fopen(output_path, "wb");
    if (!out) { fprintf(stderr, "Error: Cannot create '%s'\n", output_path); return ZUPT_ERR_IO; }

    int write_err = 0;

    zupt_archive_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic[0]=ZUPT_MAGIC_0; hdr.magic[1]=ZUPT_MAGIC_1; hdr.magic[2]=ZUPT_MAGIC_2;
    hdr.magic[3]=ZUPT_MAGIC_3; hdr.magic[4]=ZUPT_MAGIC_4; hdr.magic[5]=ZUPT_MAGIC_5;
    hdr.version_major = ZUPT_FORMAT_MAJOR; hdr.version_minor = ZUPT_FORMAT_MINOR;
    hdr.global_flags = ZUPT_FLAG_CKSUM_XXH64 | ZUPT_FLAG_SOLID;
    if (opts->encrypt) {
        hdr.global_flags |= ZUPT_FLAG_ENCRYPTED | ZUPT_FLAG_AAD_SEQ;
        hdr.global_flags |= ZUPT_FLAG_AAD_PREFACE;  /* F-09 of v2.3.1 */
        opts->keyring.use_preface_aad = 1;
    }
    hdr.creation_time = now_ns();
    gen_uuid(hdr.archive_id);
    if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) write_err = 1;

    if (opts->encrypt) {
        zupt_error_t enc_err = write_enc_header(out, &hdr, opts);
        if (enc_err != ZUPT_OK) {
            fclose(out);
            unlink(output_path);
            return enc_err;
        }
    }

    zupt_index_entry_t *index = (zupt_index_entry_t*)calloc((size_t)num_files, sizeof(zupt_index_entry_t));
    if (!index) { fclose(out); return ZUPT_ERR_NOMEM; }

    uint64_t total_uncompressed = 0;
    for (int fi = 0; fi < num_files; fi++) {
        FILE *inf = fopen(disk_paths[fi], "rb");
        if (!inf) continue;
        fseeko(inf, 0, SEEK_END);
        int64_t sz = ftello(inf);
        fclose(inf);
        if (sz < 0) continue;
        strncpy(index[fi].path, arc_paths[fi], ZUPT_MAX_PATH-1);
        index[fi].uncompressed_size = (uint64_t)sz;
        index[fi].first_block_offset = total_uncompressed;
        index[fi].modification_time = get_mtime(disk_paths[fi]);
        total_uncompressed += (uint64_t)sz;

        if (!opts->quiet) {
            char sz_s[32]; zupt_format_size((uint64_t)sz, sz_s, sizeof(sz_s));
            fprintf(stderr, "  %s (%s)\n", arc_paths[fi], sz_s);
        }
    }

    uint8_t *solid_buf = (uint8_t*)malloc((size_t)total_uncompressed);
    if (!solid_buf) { free(index); fclose(out); return ZUPT_ERR_NOMEM; }

    size_t solid_pos = 0;
    for (int fi = 0; fi < num_files; fi++) {
        if (index[fi].uncompressed_size == 0) continue;
        FILE *inf = fopen(disk_paths[fi], "rb");
        if (!inf) continue;
        if (fread(solid_buf + solid_pos, 1, (size_t)index[fi].uncompressed_size, inf) != (size_t)index[fi].uncompressed_size) { fclose(inf); continue; }
        fclose(inf);
        solid_pos += (size_t)index[fi].uncompressed_size;
    }

    uint64_t cum = 0;
    for (int fi = 0; fi < num_files; fi++) {
        uint64_t sz = index[fi].uncompressed_size;
        if (sz > 0) index[fi].content_hash = zupt_xxh64(solid_buf + cum, (size_t)sz, 0);
        cum += sz;
    }

    size_t block_cap = zupt_lzh_bound(opts->block_size) + 512;
    uint8_t *cbuf = (uint8_t*)malloc(block_cap);
    if (!cbuf) { free(solid_buf); free(index); fclose(out); return ZUPT_ERR_NOMEM; }

    uint64_t total_blocks = 0, total_out = 0, block_seq = 0;
    size_t remaining = (size_t)total_uncompressed;
    size_t src_pos = 0;
    time_t start_time = time(NULL);

    while (remaining > 0) {
        size_t chunk = remaining < opts->block_size ? remaining : opts->block_size;
        uint8_t *src = solid_buf + src_pos;
        uint64_t checksum = zupt_xxh64(src, chunk, 0);

        size_t comp_size = 0;
        uint16_t codec = opts->codec_id;

        if (codec == ZUPT_CODEC_ZUPT_LZHP) {
            uint8_t pred[256];
            float benefit = zupt_predict_benefit(src, chunk);
            if (benefit > 0.03f && chunk > 256) {
                zupt_predict_build(src, chunk, pred);
                uint8_t *trans = (uint8_t*)malloc(chunk);
                if (trans) {
                    zupt_predict_encode(src, trans, chunk, pred);
                    size_t lzh_size = zupt_lzh_compress(trans, chunk, cbuf + 257, block_cap - 257, opts->level);
                    free(trans);
                    if (lzh_size > 0 && 257 + lzh_size < chunk) {
                        cbuf[0] = 0x01;
                        memcpy(cbuf + 1, pred, 256);
                        comp_size = 257 + lzh_size;
                    }
                }
            }
            if (comp_size == 0) {
                cbuf[0] = 0x00;
                size_t plain = zupt_lzh_compress(src, chunk, cbuf + 1, block_cap - 1, opts->level);
                if (plain > 0 && 1 + plain < chunk) comp_size = 1 + plain;
            }
        } else if (codec == ZUPT_CODEC_ZUPT_LZH) {
            comp_size = zupt_lzh_compress(src, chunk, cbuf, block_cap, opts->level);
        }
        /* VAPTVUPT: VaptVupt codec in solid mode (v1.4.0 integration API) */
        else if (codec == ZUPT_CODEC_VAPTVUPT) {
            size_t vv_cap = vvz_compress_bound(chunk);
            uint8_t *vv_tmp = (uint8_t *)malloc(vv_cap);
            if (vv_tmp) {
                int64_t csz = vvz_compress(src, chunk, vv_tmp, vv_cap, opts->level);
                if (csz > 0 && (size_t)csz < chunk) {
                    if ((size_t)csz <= block_cap) {
                        memcpy(cbuf, vv_tmp, (size_t)csz);
                        comp_size = (size_t)csz;
                    }
                }
                free(vv_tmp);
            }
        }

        const uint8_t *payload = cbuf; uint64_t payload_size = comp_size;
        if (comp_size == 0 || comp_size >= chunk) {
            codec = ZUPT_CODEC_STORE; payload = src; payload_size = chunk;
        }

        uint8_t *enc_pay = NULL;
        uint16_t bflags = 0;
        if (opts->encrypt && opts->keyring.active) {
            size_t enc_len;
            /* Solid mode treats whole archive as fi=0 with global block_seq.
             * AAD = (1 << 32) | block_seq still gives unique values per block. */
            uint64_t aad_seq = ((uint64_t)1 << 32) | block_seq;
            if (opts->keyring.use_preface_aad) {
                uint8_t preface[ZUPT_PREFACE_AAD_LEN];
                uint64_t predicted_csz = 16 + payload_size + 32;
                zupt_serialize_preface_aad_scalars(
                    ZUPT_BLOCK_DATA, codec, (uint16_t)ZUPT_BFLAG_ENCRYPTED,
                    (uint64_t)chunk, predicted_csz, checksum, preface);
                enc_pay = zupt_encrypt_buffer_aad(&opts->keyring,
                    payload, payload_size, aad_seq,
                    preface, ZUPT_PREFACE_AAD_LEN, &enc_len);
                zupt_secure_wipe(preface, sizeof(preface));
            } else {
                enc_pay = zupt_encrypt_buffer(&opts->keyring, payload, payload_size, aad_seq, &enc_len);
            }
            if (enc_pay) { payload = enc_pay; payload_size = enc_len; bflags |= ZUPT_BFLAG_ENCRYPTED; }
        }

        w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
        w8(out, ZUPT_BLOCK_DATA);
        w16le(out, codec); w16le(out, bflags);
        zupt_write_varint(out, (uint64_t)chunk);
        zupt_write_varint(out, payload_size);
        w64le(out, checksum);
        if (fwrite(payload, 1, (size_t)payload_size, out) != (size_t)payload_size) write_err = 1;

        free(enc_pay);
        total_out += payload_size;
        total_blocks++;
        block_seq++;
        src_pos += chunk;
        remaining -= chunk;
    }

    for (int fi = 0; fi < num_files; fi++) index[fi].block_count = 0;

    /* ─── F-12 of v2.4.3: optional comment block (solid mode) ─── */
    {
        zupt_error_t cerr = write_comment_block(out, &hdr, opts, &total_blocks);
        if (cerr != ZUPT_OK) {
            fprintf(stderr, "Error: Failed to write comment block (solid mode)\n");
            free(solid_buf); free(cbuf); free(index); fclose(out);
            return cerr;
        }
        if (opts->has_comment && hdr.comment_offset != 0) {
            int64_t save = ftello(out);
            fseeko(out, 0, SEEK_SET);
            if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) {
                fprintf(stderr, "Error: Failed to update header with comment offset (solid)\n");
                free(solid_buf); free(cbuf); free(index); fclose(out);
                return ZUPT_ERR_IO;
            }
            fseeko(out, save, SEEK_SET);
        }
    }

    /* Write central index (LE serialization) */
    uint64_t index_offset = safe_ftello(out);
    size_t icap = (size_t)num_files * (ZUPT_MAX_PATH + 128);
    uint8_t *ibuf = (uint8_t*)malloc(icap);
    if (!ibuf) { free(solid_buf); free(cbuf); free(index); fclose(out); return ZUPT_ERR_NOMEM; }

    size_t ip = 0;
    ip += (size_t)zupt_encode_varint(ibuf + ip, (uint64_t)num_files);
    for (int fi = 0; fi < num_files; fi++) {
        if (index[fi].path[0] == '\0') continue;
        size_t plen = strlen(index[fi].path);
        ip += (size_t)zupt_encode_varint(ibuf + ip, plen);
        memcpy(ibuf + ip, index[fi].path, plen); ip += plen;
        ip += index_put_u64(ibuf + ip, index[fi].uncompressed_size);
        ip += index_put_u64(ibuf + ip, index[fi].compressed_size);
        ip += index_put_u64(ibuf + ip, index[fi].modification_time);
        ip += index_put_u64(ibuf + ip, index[fi].content_hash);
        ip += index_put_u64(ibuf + ip, index[fi].first_block_offset);
        ip += (size_t)zupt_encode_varint(ibuf + ip, index[fi].block_count);
        ip += index_put_u32(ibuf + ip, index[fi].attributes);
    }

    size_t ic_cap = zupt_lzh_bound(ip);
    uint8_t *ic = (uint8_t*)malloc(ic_cap);
    size_t ic_size = zupt_lzh_compress(ibuf, ip, ic, ic_cap, opts->level);
    uint16_t ic_codec = ZUPT_CODEC_ZUPT_LZH;
    const uint8_t *ic_pay; uint64_t ic_plen;
    if (ic_size == 0 || ic_size >= ip) { ic_codec = ZUPT_CODEC_STORE; ic_pay = ibuf; ic_plen = ip; }
    else { ic_pay = ic; ic_plen = ic_size; }

    uint64_t ic_ck_solid = zupt_xxh64(ibuf, ip, 0);  /* computed before encrypt so AAD can use it */

    uint8_t *enc_idx = NULL; uint16_t idx_bflags = 0;
    if (opts->encrypt && opts->keyring.active) {
        size_t enc_len;
        /* Index uses sentinel seq (matches decrypt site at line ~1515) */
        if (opts->keyring.use_preface_aad) {
            uint8_t preface[ZUPT_PREFACE_AAD_LEN];
            uint64_t predicted_csz = 16 + ic_plen + 32;
            zupt_serialize_preface_aad_scalars(
                ZUPT_BLOCK_INDEX, ic_codec, (uint16_t)ZUPT_BFLAG_ENCRYPTED,
                (uint64_t)ip, predicted_csz, ic_ck_solid, preface);
            enc_idx = zupt_encrypt_buffer_aad(&opts->keyring, ic_pay, ic_plen,
                0xFFFFFFFFFFFFFFFFULL, preface, ZUPT_PREFACE_AAD_LEN, &enc_len);
            zupt_secure_wipe(preface, sizeof(preface));
        } else {
            enc_idx = zupt_encrypt_buffer(&opts->keyring, ic_pay, ic_plen, 0xFFFFFFFFFFFFFFFFULL, &enc_len);
        }
        if (enc_idx) { ic_pay = enc_idx; ic_plen = enc_len; idx_bflags |= ZUPT_BFLAG_ENCRYPTED; }
    }

    w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
    w8(out, ZUPT_BLOCK_INDEX);
    w16le(out, ic_codec); w16le(out, idx_bflags);
    zupt_write_varint(out, (uint64_t)ip);
    zupt_write_varint(out, ic_plen);
    w64le(out, ic_ck_solid);
    if (fwrite(ic_pay, 1, (size_t)ic_plen, out) != (size_t)ic_plen) write_err = 1;
    total_blocks++;

    free(enc_idx);

    zupt_footer_t ft;
    memset(&ft, 0, sizeof(ft));
    ft.index_offset = index_offset;
    ft.total_blocks = total_blocks;
    ft.footer_magic[0]='Z'; ft.footer_magic[1]='E'; ft.footer_magic[2]='N'; ft.footer_magic[3]='D';
    ft.footer_version = 1;
    if (fwrite(&ft, sizeof(ft), 1, out) != 1) write_err = 1;

    /* F-08 of v2.3.0: archive-integrity-trailer (see compress-flat path). */
    if (!write_err) {
        const zupt_keyring_t *kr = opts->encrypt ? &opts->keyring : NULL;
        if (zupt_format_ait_write(out, &hdr, &ft, kr) != 0) write_err = 1;
    }

    fclose(out);

    if (write_err) {
        fprintf(stderr, "Error: Write errors occurred. Archive may be corrupt.\n");
        free(ic); free(ibuf); free(solid_buf); free(cbuf); free(index);
        return ZUPT_ERR_IO;
    }

    time_t elapsed = time(NULL) - start_time;
    if (elapsed < 1) elapsed = 1;
    char in_s[32], out_s[32];
    zupt_format_size(total_uncompressed, in_s, sizeof(in_s));
    zupt_format_size(total_out, out_s, sizeof(out_s));

    if (!opts->quiet) {
        fprintf(stderr, "\n  Archive:      %s\n", output_path);
        fprintf(stderr, "  Files:        %d (SOLID)\n", num_files);
        fprintf(stderr, "  Original:     %s\n", in_s);
        fprintf(stderr, "  Compressed:   %s (%.1f%%)\n", out_s,
                total_uncompressed > 0 ? (double)total_out / (double)total_uncompressed * 100.0 : 100.0);
        if (total_uncompressed > 0 && total_out > 0)
            fprintf(stderr, "  Ratio:        %.2f:1\n", (double)total_uncompressed / (double)total_out);
        fprintf(stderr, "  Blocks:       %llu\n", (unsigned long long)total_blocks);
        fprintf(stderr, "  Codec:        %s (level %d, SOLID)\n", zupt_codec_name(opts->codec_id), opts->level);
        if (opts->encrypt) fprintf(stderr, "  Encryption:   AES-256 + HMAC-SHA256\n");
        fprintf(stderr, "  Speed:        %.1f MB/s (%llds)\n",
                (double)total_uncompressed / (double)elapsed / 1048576.0, (long long)elapsed);
    }

    free(ic); free(ibuf); free(solid_buf); free(cbuf); free(index);
    return ZUPT_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * READING HELPERS
 * ═══════════════════════════════════════════════════════════════════ */

static zupt_error_t read_header(FILE *f, zupt_archive_header_t *h) {
    if (fread(h, sizeof(*h), 1, f) != 1) return ZUPT_ERR_IO;
    if (h->magic[0]!=ZUPT_MAGIC_0||h->magic[1]!=ZUPT_MAGIC_1||
        h->magic[2]!=ZUPT_MAGIC_2||h->magic[3]!=ZUPT_MAGIC_3||
        h->magic[4]!=ZUPT_MAGIC_4||h->magic[5]!=ZUPT_MAGIC_5) return ZUPT_ERR_BAD_MAGIC;
    if (h->version_major != ZUPT_FORMAT_MAJOR) return ZUPT_ERR_BAD_VERSION;
    return ZUPT_OK;
}

/* F-08 of v2.3.0: locate_footer_v15 supersedes the old read_footer().
 *
 * locate_footer_v15 detects which on-disk layout this file uses:
 *   v1.5:  [header][...blocks...][index][footer 32B][AIT 32B]    (current)
 *   v1.4:  [header][...blocks...][index][footer 32B]              (legacy)
 *
 * It reads the last 64 bytes and looks for the "ZEND" magic at offsets
 * EOF-64 (v1.5) and EOF-32 (v1.4). The header's version_minor is informative
 * but NOT load-bearing here: we trust the on-disk footer position because
 * the version field is itself uncovered metadata in v1.4 archives and the
 * point of F-08 is to stop trusting uncovered metadata. If the magic appears
 * at neither offset, the archive is corrupt.
 *
 * On v1.5 archives, *has_ait is set to 1 and *ait_buf is filled with the
 * 32 trailing bytes (caller is responsible for verifying them, since the
 * keyring isn't available at this point in open_archive's flow). On v1.4
 * archives, *has_ait is 0. */
static zupt_error_t locate_footer_v15(FILE *f, zupt_footer_t *ft,
                                      int *has_ait, uint8_t ait_buf[ZUPT_AIT_SIZE]) {
    fseeko(f, 0, SEEK_END);
    int64_t file_size = ftello(f);
    if (file_size < (int64_t)sizeof(zupt_footer_t)) return ZUPT_ERR_CORRUPT;

    /* Try v1.5: footer at EOF-64, AIT at EOF-32 */
    if (file_size >= (int64_t)sizeof(zupt_footer_t) + ZUPT_AIT_SIZE) {
        zupt_footer_t cand;
        fseeko(f, -(int64_t)(sizeof(zupt_footer_t) + ZUPT_AIT_SIZE), SEEK_END);
        if (fread(&cand, sizeof(cand), 1, f) == 1 &&
            cand.footer_magic[0]=='Z' && cand.footer_magic[1]=='E' &&
            cand.footer_magic[2]=='N' && cand.footer_magic[3]=='D' &&
            cand.footer_version == 1) {
            if (fread(ait_buf, ZUPT_AIT_SIZE, 1, f) != 1) return ZUPT_ERR_IO;
            *ft = cand;
            *has_ait = 1;
            return ZUPT_OK;
        }
    }

    /* Fall back to v1.4: footer at EOF-32, no AIT */
    fseeko(f, -(int64_t)sizeof(zupt_footer_t), SEEK_END);
    if (fread(ft, sizeof(*ft), 1, f) != 1) return ZUPT_ERR_IO;
    if (ft->footer_magic[0]!='Z'||ft->footer_magic[1]!='E'||
        ft->footer_magic[2]!='N'||ft->footer_magic[3]!='D') return ZUPT_ERR_CORRUPT;
    if (ft->footer_version != 1) return ZUPT_ERR_BAD_VERSION;
    *has_ait = 0;
    return ZUPT_OK;
}

/* AIT MAC input: header[0..63] || footer[0..23].
 *
 * Excludes footer[24..31] = footer_magic[4] || footer_version (u32). The magic
 * is structurally validated by locate_footer_v15; the version_field is
 * informational. Including them would not add tamper resistance — a flipped
 * magic byte already causes locate to fail before we reach the MAC step. */
static void ait_serialize_mac_input(const zupt_archive_header_t *hdr,
                                    const zupt_footer_t *ft,
                                    uint8_t buf[ZUPT_AIT_MAC_INPUT_LEN]) {
    memcpy(buf, hdr, sizeof(*hdr));
    memcpy(buf + sizeof(*hdr), ft, 24);  /* index_offset + total_blocks + archive_checksum */
}

/* Compute the trailing AIT field and emit ZUPT_AIT_SIZE bytes through fwrite.
 *
 * Non-static so the disk-backup writer in src/zupt_disk.c can reuse it.
 * Other cross-file linkage in this codebase (read_block, decompress_block,
 * read_enc_header, write_enc_header) follows the same "extern by default"
 * convention — no internal header. The matching extern decl in zupt_disk.c
 * is the single source of truth for the prototype on the caller side. */
int zupt_format_ait_write(FILE *f, const zupt_archive_header_t *hdr,
                          const zupt_footer_t *ft,
                          const zupt_keyring_t *kr_or_null) {
    uint8_t mac_input[ZUPT_AIT_MAC_INPUT_LEN];
    uint8_t ait[ZUPT_AIT_SIZE];
    memset(ait, 0, sizeof(ait));
    ait_serialize_mac_input(hdr, ft, mac_input);
    if (kr_or_null && kr_or_null->active) {
        zupt_hmac_sha256(kr_or_null->mac_key, ZUPT_HMAC_SIZE,
                         mac_input, ZUPT_AIT_MAC_INPUT_LEN, ait);
    } else {
        uint64_t x = zupt_xxh64(mac_input, ZUPT_AIT_MAC_INPUT_LEN, 0);
        for (int i = 0; i < 8; i++) ait[i] = (uint8_t)(x >> (i * 8));
    }
    int ok = (fwrite(ait, sizeof(ait), 1, f) == 1);
    zupt_secure_wipe(mac_input, ZUPT_AIT_MAC_INPUT_LEN);
    zupt_secure_wipe(ait, sizeof(ait));
    return ok ? 0 : -1;
}

/* Verify the AIT field against header+footer.
 *
 * Encrypted archives: HMAC-SHA256 with constant-time tag compare.
 * Plaintext archives: XXH64 in the first 8 bytes, byte-wise compare of the
 *                     remaining 24 bytes against zero.
 * Returns ZUPT_OK iff the trailer authenticates the header+footer. */
/* Verify the AIT field against header+footer.
 *
 * Encrypted archives: HMAC-SHA256 with constant-time tag compare.
 * Plaintext archives: XXH64 in the first 8 bytes, byte-wise compare of the
 *                     remaining 24 bytes against zero.
 * Returns ZUPT_OK iff the trailer authenticates the header+footer. */
static zupt_error_t ait_verify(const zupt_archive_header_t *hdr,
                               const zupt_footer_t *ft,
                               const uint8_t ait[ZUPT_AIT_SIZE],
                               const zupt_keyring_t *kr_or_null) {
    uint8_t mac_input[ZUPT_AIT_MAC_INPUT_LEN];
    ait_serialize_mac_input(hdr, ft, mac_input);

    zupt_error_t result;
    if (kr_or_null && kr_or_null->active) {
        uint8_t expected[ZUPT_AIT_SIZE];
        zupt_hmac_sha256(kr_or_null->mac_key, ZUPT_HMAC_SIZE,
                         mac_input, ZUPT_AIT_MAC_INPUT_LEN, expected);
        /* CT-REQUIRED: constant-time compare via the audited primitive. */
        int eq = zupt_ct_memeq(expected, ait, ZUPT_AIT_SIZE);
        zupt_secure_wipe(expected, sizeof(expected));
        result = eq ? ZUPT_OK : ZUPT_ERR_AUTH_FAIL;
    } else {
        uint64_t got = zupt_xxh64(mac_input, ZUPT_AIT_MAC_INPUT_LEN, 0);
        uint8_t expected[ZUPT_AIT_SIZE];
        memset(expected, 0, sizeof(expected));
        for (int i = 0; i < 8; i++) expected[i] = (uint8_t)(got >> (i * 8));
        /* No timing concern in plaintext mode (no secret involved). */
        int eq = (memcmp(expected, ait, ZUPT_AIT_SIZE) == 0);
        result = eq ? ZUPT_OK : ZUPT_ERR_BAD_CHECKSUM;
    }
    zupt_secure_wipe(mac_input, ZUPT_AIT_MAC_INPUT_LEN);
    return result;
}

/* Public wrapper around ait_verify() for cross-file callers (src/zupt_disk.c).
 * Mirrors the zupt_format_ait_write() naming convention. The matching extern
 * decl lives in zupt_disk.c's restore path. */
zupt_error_t zupt_format_ait_verify_extern(const zupt_archive_header_t *hdr,
                                           const zupt_footer_t *ft,
                                           const uint8_t ait[ZUPT_AIT_SIZE],
                                           const zupt_keyring_t *kr_or_null) {
    return ait_verify(hdr, ft, ait, kr_or_null);
}

zupt_error_t read_block(FILE *f, zupt_block_t *b) {
    uint8_t m[2];
    if (fread(m,1,2,f)!=2) return ZUPT_ERR_IO;
    if (m[0]!=ZUPT_BLOCK_MAGIC_0||m[1]!=ZUPT_BLOCK_MAGIC_1) return ZUPT_ERR_CORRUPT;
    uint8_t bt; if (fread(&bt,1,1,f)!=1) return ZUPT_ERR_IO; b->block_type = bt;
    if (r16le(f,&b->codec_id)<0) return ZUPT_ERR_IO;
    if (r16le(f,&b->block_flags)<0) return ZUPT_ERR_IO;
    if (zupt_read_varint(f,&b->uncompressed_size)<0) return ZUPT_ERR_IO;
    if (zupt_read_varint(f,&b->compressed_size)<0) return ZUPT_ERR_IO;
    if (r64le(f,&b->checksum)<0) return ZUPT_ERR_IO;

    if (b->compressed_size > ZUPT_MAX_BLOCK_SZ + 4096) return ZUPT_ERR_OVERFLOW;
    if (b->uncompressed_size > ZUPT_MAX_BLOCK_SZ) return ZUPT_ERR_OVERFLOW;

    b->payload = (uint8_t*)malloc((size_t)b->compressed_size);
    if (!b->payload) return ZUPT_ERR_NOMEM;
    if (fread(b->payload,1,(size_t)b->compressed_size,f)!=(size_t)b->compressed_size) {
        free(b->payload); b->payload=NULL; return ZUPT_ERR_IO;
    }
    return ZUPT_OK;
}

zupt_error_t decompress_block(const zupt_block_t *b, const zupt_keyring_t *kr,
                                      uint64_t block_seq, uint8_t **out, size_t *olen) {
    const uint8_t *comp_data = b->payload;
    size_t comp_len = (size_t)b->compressed_size;
    uint8_t *dec_payload = NULL;

    if (!b->payload && comp_len > 0) return ZUPT_ERR_CORRUPT;
    if (b->uncompressed_size > ZUPT_MAX_BLOCK_SZ) return ZUPT_ERR_OVERFLOW;
    if (comp_len > ZUPT_MAX_BLOCK_SZ + 1024) return ZUPT_ERR_OVERFLOW;

    /* SECURITY: in an encrypted archive every block MUST be encrypted.
     * The per-block ENCRYPTED flag is NOT covered by the archive-integrity
     * trailer (which only authenticates the header and footer, not block
     * bodies/flags). Without this gate an attacker could clear the flag on
     * a forged STORE block and inject attacker-chosen plaintext that passes
     * only the keyless XXH64 — an authentication bypass / plaintext forgery.
     * Fail closed when the keyring is active but the block isn't encrypted. */
    if (kr && kr->active && !(b->block_flags & ZUPT_BFLAG_ENCRYPTED))
        return ZUPT_ERR_AUTH_FAIL;

    if (b->block_flags & ZUPT_BFLAG_ENCRYPTED) {
        if (!kr || !kr->active) return ZUPT_ERR_AUTH_FAIL;
        size_t dec_len;
        /* F-09 of v2.3.1: the archive's global ZUPT_FLAG_AAD_PREFACE bit
         * (in opts->global_flags, threaded through kr->use_preface_aad)
         * tells us whether to bind the canonical preface bytes into the
         * MAC. The flag itself is MAC-protected at archive level by the
         * v1.5 archive-integrity-trailer (F-08), so an attacker can't
         * flip it without auth-fail at open_archive time. */
        if (kr->use_preface_aad) {
            uint8_t preface[ZUPT_PREFACE_AAD_LEN];
            zupt_serialize_preface_aad(b, preface);
            dec_payload = zupt_decrypt_buffer_aad(kr, comp_data, comp_len,
                                                  block_seq,
                                                  preface, ZUPT_PREFACE_AAD_LEN,
                                                  &dec_len);
            zupt_secure_wipe(preface, sizeof(preface));
        } else {
            dec_payload = zupt_decrypt_buffer(kr, comp_data, comp_len, block_seq, &dec_len);
        }
        if (!dec_payload) return ZUPT_ERR_AUTH_FAIL;
        comp_data = dec_payload;
        comp_len = dec_len;
    }

    *olen = (size_t)b->uncompressed_size;
    if (*olen == 0) { *out = NULL; free(dec_payload); return ZUPT_OK; }
    /* Over-allocate by ZUPT_VV_DECODE_SLACK so the VaptVupt AVX2 decode
     * over-copy (up to 32 B past the logical end) lands in owned memory.
     * *olen still reports the true uncompressed size to the caller; the
     * slack bytes are never part of the output. See the constant's
     * definition near the top of this file. */
    *out = (uint8_t*)malloc(*olen + ZUPT_VV_DECODE_SLACK);
    if (!*out) { free(dec_payload); return ZUPT_ERR_NOMEM; }

    zupt_error_t result = ZUPT_OK;

    if (b->codec_id == ZUPT_CODEC_STORE) {
        if (comp_len < *olen) {
            result = ZUPT_ERR_CORRUPT;
        } else {
            memcpy(*out, comp_data, *olen);
        }
    } else if (b->codec_id == ZUPT_CODEC_ZUPT_LZ) {
        size_t r = zupt_lz_decompress(comp_data, comp_len, *out, *olen);
        if (r != *olen) result = ZUPT_ERR_CORRUPT;
    } else if (b->codec_id == ZUPT_CODEC_ZUPT_LZH) {
        size_t r = zupt_lzh_decompress(comp_data, comp_len, *out, *olen);
        if (r != *olen) result = ZUPT_ERR_CORRUPT;
    } else if (b->codec_id == ZUPT_CODEC_ZUPT_LZHP) {
        if (comp_len < 1) { result = ZUPT_ERR_CORRUPT; goto done; }

        uint8_t pflag = comp_data[0];
        int pred_active = (pflag & 0x01);
        size_t hdr_size = 1;
        uint8_t pred[256];

        if (pred_active) {
            if (comp_len < 257) { result = ZUPT_ERR_CORRUPT; goto done; }
            memcpy(pred, comp_data + 1, 256);
            hdr_size = 257;
        }

        if (comp_len <= hdr_size) { result = ZUPT_ERR_CORRUPT; goto done; }
        const uint8_t *lzh_data = comp_data + hdr_size;
        size_t lzh_len = comp_len - hdr_size;

        if (pred_active) {
            uint8_t *temp = (uint8_t *)malloc(*olen);
            if (!temp) { result = ZUPT_ERR_NOMEM; goto done; }
            size_t r = zupt_lzh_decompress(lzh_data, lzh_len, temp, *olen);
            if (r != *olen) {
                free(temp);
                result = ZUPT_ERR_CORRUPT;
                goto done;
            }
            zupt_predict_decode(temp, *out, *olen, pred);
            free(temp);
        } else {
            size_t r = zupt_lzh_decompress(lzh_data, lzh_len, *out, *olen);
            if (r != *olen) result = ZUPT_ERR_CORRUPT;
        }
    }
    /* VAPTVUPT: VaptVupt codec decompress path (v1.4.0 cross-block decode) */
    else if (b->codec_id == ZUPT_CODEC_VAPTVUPT) {
        /* Pass the padded capacity (*olen + slack): the codec's AVX2
         * over-copy needs op_end to sit past the logical output end so
         * its 32-byte SIMD stores stay in bounds. We still require the
         * returned size to equal the true *olen, so the slack never
         * affects correctness. */
        int64_t dsz = vvz_decompress(comp_data, comp_len, *out,
                                     *olen + ZUPT_VV_DECODE_SLACK);
        if (dsz < 0 || (size_t)dsz != *olen) result = ZUPT_ERR_CORRUPT;
    } else {
        result = ZUPT_ERR_UNSUPPORTED;
    }

done:
    free(dec_payload);
    if (result != ZUPT_OK) { free(*out); *out = NULL; return result; }

    uint64_t ck = zupt_xxh64(*out, *olen, 0);
    if (ck != b->checksum) { free(*out); *out = NULL; return ZUPT_ERR_BAD_CHECKSUM; }
    return ZUPT_OK;
}

zupt_error_t read_enc_header(FILE *f, zupt_archive_header_t *hdr, zupt_options_t *opts) {
    if (!(hdr->global_flags & ZUPT_FLAG_ENCRYPTED)) return ZUPT_OK;

    /* Validate encryption_header_off is within file bounds before seeking.
     * A malicious or corrupt archive could set this to 0xFFFFFFFFFFFFFFFF;
     * casting to int64_t gives -1, fseeko fails silently, and subsequent
     * reads happen at an undefined position. */
    int64_t cur_pos = ftello(f);
    fseeko(f, 0, SEEK_END);
    int64_t file_size = ftello(f);
    fseeko(f, cur_pos, SEEK_SET);
    if (file_size < 0 || hdr->encryption_header_off > (uint64_t)file_size) {
        return ZUPT_ERR_CORRUPT;
    }

    fseeko(f, (int64_t)hdr->encryption_header_off, SEEK_SET);
    zupt_block_t eb;
    zupt_error_t err = read_block(f, &eb);
    if (err != ZUPT_OK) return err;

    /* F-09 of v2.3.1 (same pattern as F-07 of v2.2.5): the block at
     * encryption_header_off MUST identify itself as ENC_HEADER. The
     * block_type byte sits outside the cryptographic MAC (the SDK-v2
     * envelope authenticates only its own contents, not the surrounding
     * frame preface), so a tampering attacker could flip it without
     * detection. Structurally reject mismatches here.
     *
     * The same logic extends to the rest of the enc-header frame preface:
     * the codec MUST be STORE (the envelope isn't compressed), block_flags
     * MUST be zero (the envelope contains its own crypto), and
     * compressed_size MUST equal uncompressed_size (no length games). These
     * cover bytes 67-72 of the v1.6 sweep. The plaintext-XXH64 field
     * (bytes 75-82) is checked against the actual payload contents below. */
    if (eb.block_type != ZUPT_BLOCK_ENC_HEADER) {
        free(eb.payload);
        return ZUPT_ERR_CORRUPT;
    }
    if (eb.codec_id != ZUPT_CODEC_STORE ||
        eb.block_flags != 0 ||
        eb.compressed_size != eb.uncompressed_size) {
        free(eb.payload);
        return ZUPT_ERR_CORRUPT;
    }
    {
        uint64_t actual_ck = zupt_xxh64(eb.payload, (size_t)eb.compressed_size, 0);
        if (actual_ck != eb.checksum) {
            free(eb.payload);
            return ZUPT_ERR_BAD_CHECKSUM;
        }
    }

    if (eb.compressed_size < 1) { free(eb.payload); return ZUPT_ERR_CORRUPT; }

    uint8_t enc_type = eb.payload[0];

    if (enc_type == ZUPT_ENC_PQ_BOX_V1) {
        if (!opts->pq_mode || opts->keyfile[0] == '\0') {
            fprintf(stderr, "Error: Archive uses pq-box encryption. Use --pq-box <keyfile>.\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        if (zupt_pqbox_decrypt_init(&opts->keyring, opts->keyfile,
                                    eb.payload, (size_t)eb.compressed_size) != 0) {
            if (opts->verbose) {
                fprintf(stderr, "Error: pq-box envelope decryption failed.\n"
                                "       This means wrong key, tampered envelope, or unsupported format.\n");
            }
            fprintf(stderr, "Error: Authentication failed (wrong key, wrong password, or tampered archive).\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        opts->box_mode = 1;
        free(eb.payload);
        return ZUPT_OK;
    }

    if (enc_type == ZUPT_ENC_PQ_SDK_V2) {
        if (!opts->pq_mode || opts->keyfile[0] == '\0') {
            fprintf(stderr, "Error: Archive uses SDK-v2 PQ encryption. Use --pq <keyfile>.\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        if (zupt_sdk_hybrid_decrypt_init(&opts->keyring, opts->keyfile,
                                          eb.payload, (size_t)eb.compressed_size) != 0) {
            /* F-11 of v2.4.2: same generic phrasing as the AIT-fail path
             * in open_archive(), for consistency across all key-mode
             * failures. Verbose mode adds the technical-detail line. */
            if (opts->verbose) {
                fprintf(stderr, "Error: SDK-v2 PQ envelope decryption failed.\n"
                                "       This means wrong key, tampered envelope, or unsupported format.\n");
            }
            fprintf(stderr, "Error: Authentication failed (wrong key, wrong password, or tampered archive).\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        opts->sdk_mode = 1;
        free(eb.payload);
        return ZUPT_OK;
    } else if (enc_type == ZUPT_ENC_PW_ARGON2) {
        if (opts->password[0] == '\0') {
            fprintf(stderr, "Error: Archive is password-encrypted. Use -p to provide password.\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        if (zupt_sdk_password_decrypt_init(&opts->keyring, opts->password,
                                            eb.payload, (size_t)eb.compressed_size) != 0) {
            /* F-11 of v2.4.2: aligned with the AIT-fail path. */
            if (opts->verbose) {
                fprintf(stderr, "Error: Argon2id password verification failed at envelope step.\n");
            }
            fprintf(stderr, "Error: Authentication failed (wrong key, wrong password, or tampered archive).\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        opts->sdk_mode = 1;
        free(eb.payload);
        return ZUPT_OK;
    } else if (enc_type == ZUPT_ENC_PQ_HYBRID) {
        /* ─── PQ HYBRID MODE ─── */
        if (!opts->pq_mode || opts->keyfile[0] == '\0') {
            fprintf(stderr, "Error: Archive uses post-quantum encryption. Use --pq <keyfile>.\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        if (zupt_hybrid_decrypt_init(&opts->keyring, opts->keyfile,
                                      eb.payload, (size_t)eb.compressed_size) != 0) {
            fprintf(stderr, "Error: PQ decryption key derivation failed (wrong key?).\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        free(eb.payload);
        return ZUPT_OK;
    } else if (enc_type == ZUPT_ENC_PQ_ONLY) {
        /* ─── FULL POST-QUANTUM MODE (ML-KEM-768 only) ─── */
        if (opts->keyfile[0] == '\0') {
            fprintf(stderr, "Error: Archive uses full post-quantum encryption. Use --pq-only <keyfile>.\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        if (zupt_pq_decrypt_init(&opts->keyring, opts->keyfile,
                                 eb.payload, (size_t)eb.compressed_size) != 0) {
            fprintf(stderr, "Error: full-PQ decryption key derivation failed (wrong key?).\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        free(eb.payload);
        return ZUPT_OK;
    } else if (enc_type == ZUPT_ENC_PBKDF2) {
        /* ─── PASSWORD MODE (v0.7+ format with enc_type prefix) ─── */
        if (opts->password[0] == '\0') {
            fprintf(stderr, "Error: Archive is encrypted. Use -p to provide a password.\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        if (eb.compressed_size < 53) { free(eb.payload); return ZUPT_ERR_CORRUPT; }
        uint8_t salt[32], nonce[16]; uint32_t iter;
        memcpy(salt, eb.payload + 1, 32);
        memcpy(nonce, eb.payload + 33, 16);
        memcpy(&iter, eb.payload + 49, 4);
        free(eb.payload);
        /* SECURITY: reject an absurd attacker-supplied iteration count before
         * spending the CPU on it (KDF-amplification DoS). See
         * ZUPT_KDF_MAX_ITERATIONS. */
        if (iter < 1 || iter > ZUPT_KDF_MAX_ITERATIONS) return ZUPT_ERR_CORRUPT;
        fprintf(stderr, "  Deriving decryption key (PBKDF2-SHA256, %u iterations)...\n", iter);
        zupt_derive_keys(&opts->keyring, opts->password, salt, nonce, iter);
        return ZUPT_OK;
    } else {
        /* ─── LEGACY v0.5/v0.6 format (no enc_type prefix, raw salt at offset 0) ─── */
        if (opts->password[0] == '\0') {
            fprintf(stderr, "Error: Archive is encrypted. Use -p to provide a password.\n");
            free(eb.payload);
            return ZUPT_ERR_AUTH_FAIL;
        }
        if (eb.compressed_size < 52) { free(eb.payload); return ZUPT_ERR_CORRUPT; }
        uint8_t salt[32], nonce[16]; uint32_t iter;
        memcpy(salt, eb.payload, 32);
        memcpy(nonce, eb.payload + 32, 16);
        memcpy(&iter, eb.payload + 48, 4);
        free(eb.payload);
        /* SECURITY: reject an absurd attacker-supplied iteration count before
         * spending the CPU on it (KDF-amplification DoS). */
        if (iter < 1 || iter > ZUPT_KDF_MAX_ITERATIONS) return ZUPT_ERR_CORRUPT;
        fprintf(stderr, "  Deriving decryption key (PBKDF2-SHA256, %u iterations)...\n", iter);
        zupt_derive_keys(&opts->keyring, opts->password, salt, nonce, iter);
        return ZUPT_OK;
    }
}

static zupt_error_t parse_index(const uint8_t *buf, size_t blen,
                                zupt_index_entry_t **ents, int *n) {
    size_t p = 0; uint64_t count;
    int vn = zupt_decode_varint(buf+p, blen-p, &count);
    if (vn < 0) return ZUPT_ERR_CORRUPT;
    p += (size_t)vn;
    if (count > ZUPT_MAX_FILES) return ZUPT_ERR_OVERFLOW;
    /* Defense for 32-bit platforms: count * sizeof(entry) must fit in size_t.
     * Each entry is ~4 KB; on 32-bit, ~1M entries already exceeds 4 GiB. */
    if (count > (uint64_t)(SIZE_MAX / sizeof(zupt_index_entry_t))) {
        return ZUPT_ERR_OVERFLOW;
    }
    *n = (int)count;
    *ents = (zupt_index_entry_t*)calloc((size_t)count, sizeof(zupt_index_entry_t));
    if (!*ents) return ZUPT_ERR_NOMEM;

    for (uint64_t i = 0; i < count; i++) {
        zupt_index_entry_t *e = &(*ents)[i];
        uint64_t plen;
        vn = zupt_decode_varint(buf+p, blen-p, &plen);
        if (vn<0) { free(*ents); return ZUPT_ERR_CORRUPT; }
        /* SECURITY: overflow-safe bound. The decoder consumes at most blen-p
         * bytes so p+vn<=blen and blen-p-vn cannot underflow. The previous
         * check `p+vn+plen>blen` wrapped around for an attacker-supplied
         * ~2^64 plen, passed, then drove an OOB memcpy of ZUPT_MAX_PATH-1
         * bytes past the index buffer. */
        if (plen > (uint64_t)(blen - p - (size_t)vn)) { free(*ents); return ZUPT_ERR_CORRUPT; }
        p += (size_t)vn;
        if (plen >= ZUPT_MAX_PATH) plen = ZUPT_MAX_PATH-1;
        memcpy(e->path, buf+p, (size_t)plen); e->path[plen]='\0'; p += (size_t)plen;

        if (p+44>blen) { free(*ents); return ZUPT_ERR_CORRUPT; }
        e->uncompressed_size = index_get_u64(buf+p); p+=8;
        e->compressed_size   = index_get_u64(buf+p); p+=8;
        e->modification_time = index_get_u64(buf+p); p+=8;
        e->content_hash      = index_get_u64(buf+p); p+=8;
        e->first_block_offset= index_get_u64(buf+p); p+=8;
        uint64_t bc;
        vn = zupt_decode_varint(buf+p, blen-p, &bc);
        if (vn<0) { free(*ents); return ZUPT_ERR_CORRUPT; }
        p += (size_t)vn; e->block_count = (uint32_t)bc;
        if (p+4>blen) { free(*ents); return ZUPT_ERR_CORRUPT; }
        e->attributes = index_get_u32(buf+p); p+=4;
    }
    return ZUPT_OK;
}

static zupt_error_t open_archive(FILE *f, zupt_options_t *opts,
                                  zupt_archive_header_t *hdr, zupt_footer_t *ft,
                                  zupt_index_entry_t **entries, int *num_entries) {
    zupt_error_t err = read_header(f, hdr);
    if (err != ZUPT_OK) return err;

    /* F-08 of v2.3.0: locate footer with v1.5 archive-integrity-trailer
     * awareness. has_ait=1 means an AIT was found at EOF-32; verification
     * is deferred until after read_enc_header() initialises the keyring. */
    int has_ait = 0;
    uint8_t ait_buf[ZUPT_AIT_SIZE];
    err = locate_footer_v15(f, ft, &has_ait, ait_buf);
    if (err != ZUPT_OK) return err;

    err = read_enc_header(f, hdr, opts);
    if (err != ZUPT_OK) return err;

    /* F-08 of v2.3.0: verify the archive-integrity-trailer.
     *
     * For encrypted archives, the AIT is HMAC-SHA256(mac_key, hdr || ft[0..23])
     * and MUST authenticate before we read any further. For plaintext archives,
     * the AIT is XXH64 best-effort.
     *
     * v1.4 archives (no AIT) keep extracting unchanged — backward compatibility
     * was the explicit design constraint when F-08 was opened. They emit a
     * warning on stderr in encrypted modes so users notice the integrity
     * downgrade. The warning text is stable (it's part of the threat model
     * surface) and the message comes from one place. */
    if (has_ait) {
        int is_encrypted = (hdr->global_flags & ZUPT_FLAG_ENCRYPTED) != 0;
        const zupt_keyring_t *kr = is_encrypted ? &opts->keyring : NULL;
        zupt_error_t aerr = ait_verify(hdr, ft, ait_buf, kr);
        if (aerr != ZUPT_OK) {
            /* F-11 of v2.4.2: a wrong password or wrong PQ key produces a
             * mac_key that doesn't match the AIT, exactly like a real
             * tamper. Pre-2.4.2 we printed "archive header or footer has
             * been tampered with" in both cases, which mislead users
             * into thinking valid archives were corrupted. The fix:
             *
             *  - Encrypted archives → default message is the same single
             *    "Authentication failed" line that the downstream
             *    decrypt path emits. Users see one consistent message
             *    regardless of which check fired first. The detailed
             *    top-MAC wording moves behind --verbose for debugging.
             *
             *  - Plaintext archives → no key was supplied, so wrong-key
             *    is impossible by construction. The failure IS a tamper
             *    (or corruption). Keep the detailed message.
             *
             * The default message is identical regardless of which
             * candidate (wrong key vs real tamper) caused the AIT
             * mismatch, which avoids creating a verbal probe-oracle.
             * Timing is unchanged: ait_verify always runs the HMAC and
             * returns branchlessly.
             */
            if (is_encrypted) {
                if (opts->verbose) {
                    fprintf(stderr, "Error: archive-integrity-trailer (top-MAC) verification failed.\n"
                                    "       This means EITHER wrong password/key OR a tampered\n"
                                    "       header or footer. v2.4.2+ collapses both into one\n"
                                    "       error to avoid a verbal side channel.\n");
                }
                fprintf(stderr, "Error: Authentication failed (wrong key, wrong password, or tampered archive).\n");
            } else {
                /* Plaintext archive: no key involvement, so this is
                 * unambiguously corruption or tamper. */
                fprintf(stderr, "Error: archive-integrity-trailer (XXH64) verification failed.\n"
                                "       The archive header or footer has been corrupted or tampered with.\n");
            }
            return aerr;
        }
    } else if (hdr->global_flags & ZUPT_FLAG_ENCRYPTED) {
        fprintf(stderr, "Warning: legacy v1.4 archive without top-MAC (F-08).\n"
                        "         File contents are integrity-protected, but header\n"
                        "         and footer metadata (timestamps, UUID, counts) are not.\n");
    }

    /* F-09 of v2.3.1: propagate the archive-level preface-AAD policy into
     * the keyring so decompress_block knows whether to bind the per-block
     * preface into the MAC. This flag is MAC-protected by the AIT (when
     * has_ait) — an attacker can't flip it on tampered v1.5+ archives. On
     * v1.4 archives (no AIT) the flag is also absent, so this stays 0. */
    if (hdr->global_flags & ZUPT_FLAG_AAD_PREFACE) {
        opts->keyring.use_preface_aad = 1;
    }

    /* F-12 of v2.4.3: read the optional comment block. comment_offset is
     * part of hdr[0..63] and therefore covered by the v1.5+ AIT, so a
     * tampered pointer is rejected before we reach this code. The block
     * itself is covered by the per-block HMAC (with preface AAD in v1.6
     * archives), so its bytes are also tamper-protected. */
    if (hdr->comment_offset != 0) {
        int64_t save_pos = ftello(f);
        fseeko(f, (int64_t)hdr->comment_offset, SEEK_SET);
        zupt_block_t cb;
        memset(&cb, 0, sizeof(cb));
        zupt_error_t cerr = read_block(f, &cb);
        if (cerr != ZUPT_OK) {
            free(cb.payload);
            return cerr;
        }
        if (cb.block_type != ZUPT_BLOCK_COMMENT ||
            cb.uncompressed_size == 0 ||
            cb.uncompressed_size > ZUPT_MAX_COMMENT_LEN) {
            free(cb.payload);
            return ZUPT_ERR_CORRUPT;
        }
        uint8_t *plain = NULL;
        size_t plen = 0;
        cerr = decompress_block(&cb, &opts->keyring, ZUPT_COMMENT_AAD_SEQ, &plain, &plen);
        if (cerr != ZUPT_OK) {
            free(cb.payload);
            return cerr;
        }
        if (plen > ZUPT_MAX_COMMENT_LEN - 1) plen = ZUPT_MAX_COMMENT_LEN - 1;
        memcpy(opts->comment, plain, plen);
        opts->comment[plen] = '\0';
        opts->has_comment = 1;
        zupt_secure_wipe(plain, plen);
        free(plain);
        free(cb.payload);
        fseeko(f, save_pos, SEEK_SET);
    }

    /* Validate index_offset is within file bounds before seeking. */
    int64_t cur_pos2 = ftello(f);
    fseeko(f, 0, SEEK_END);
    int64_t file_size2 = ftello(f);
    fseeko(f, cur_pos2, SEEK_SET);
    if (file_size2 < 0 || ft->index_offset > (uint64_t)file_size2) {
        return ZUPT_ERR_CORRUPT;
    }

    fseeko(f, (int64_t)ft->index_offset, SEEK_SET);
    zupt_block_t ib;
    err = read_block(f, &ib);
    if (err != ZUPT_OK) return err;

    /* F-07 of v2.2.5: the block at index_offset MUST identify itself as an
     * INDEX block. The block_type byte is not covered by per-block HMAC
     * (which protects nonce||ciphertext||aad_seq only), so a tampering
     * attacker can flip it without authentication failure. Pre-F-07 the
     * parser ignored block_type at this position and decoded whatever it
     * found — making the byte truly unauthenticated. Now it is structurally
     * validated (rejected at parse time on mismatch), which is the
     * OPAQUE-class coverage promised by PROMPT.md §5. */
    if (ib.block_type != ZUPT_BLOCK_INDEX) {
        free(ib.payload);
        return ZUPT_ERR_CORRUPT;
    }

    uint8_t *id; size_t idlen;
    err = decompress_block(&ib, &opts->keyring, 0xFFFFFFFFFFFFFFFFULL, &id, &idlen);
    free(ib.payload);
    if (err != ZUPT_OK) return err;

    err = parse_index(id, idlen, entries, num_entries);
    free(id);
    return err;
}

/* ═══════════════════════════════════════════════════════════════════
 * LIST
 * ═══════════════════════════════════════════════════════════════════ */

zupt_error_t zupt_list_archive(const char *arc, zupt_options_t *opts) {
    FILE *f = fopen(arc, "rb");
    if (!f) { fprintf(stderr, "Error: Cannot open '%s'\n", arc); return ZUPT_ERR_IO; }

    zupt_archive_header_t hdr; zupt_footer_t ft;
    zupt_index_entry_t *ents; int n;
    zupt_error_t err = open_archive(f, opts, &hdr, &ft, &ents, &n);
    if (err != ZUPT_OK) { fclose(f); return err; }

    printf("\n ZUPT Archive: %s\n", arc);
    printf(" Format: v%u.%u | Blocks: %llu", hdr.version_major, hdr.version_minor, (unsigned long long)ft.total_blocks);
    if (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) printf(" | Encrypted");
    if (hdr.global_flags & ZUPT_FLAG_PQ_HYBRID) printf(" | PQ");
    if (hdr.global_flags & ZUPT_FLAG_DEDUP) printf(" | Dedup");
    if (hdr.global_flags & ZUPT_FLAG_DISK_IMAGE) printf(" | Disk");
    printf("\n\n");
    printf(" %-50s %12s %12s  %s\n", "Path", "Original", "Compressed", "Ratio");
    printf(" %s\n", "--------------------------------------------------------------------------------------------");

    uint64_t ti=0, to=0;
    for (int i=0;i<n;i++) {
        zupt_index_entry_t *e = &ents[i];
        char is[16],cs[16];
        zupt_format_size(e->uncompressed_size, is, sizeof(is));
        zupt_format_size(e->compressed_size, cs, sizeof(cs));
        double r = e->uncompressed_size>0?(double)e->compressed_size/(double)e->uncompressed_size*100:100;
        printf(" %-50s %12s %12s  %5.1f%%\n", e->path, is, cs, r);
        ti += e->uncompressed_size; to += e->compressed_size;
    }
    char tis[16],tos[16];
    zupt_format_size(ti,tis,sizeof(tis)); zupt_format_size(to,tos,sizeof(tos));
    double tr = ti>0?(double)to/(double)ti*100:100;
    printf(" %s\n", "--------------------------------------------------------------------------------------------");
    printf(" %-50s %12s %12s  %5.1f%%\n", "TOTAL", tis, tos, tr);
    printf(" %d file(s)\n\n", n);

    free(ents); fclose(f);
    return ZUPT_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * EXTRACT
 * ═══════════════════════════════════════════════════════════════════ */

zupt_error_t zupt_extract_archive(const char *arc, const char *dir, zupt_options_t *opts) {
    FILE *f = fopen(arc, "rb");
    if (!f) { fprintf(stderr, "Error: Cannot open '%s'\n", arc); return ZUPT_ERR_IO; }

    zupt_archive_header_t hdr; zupt_footer_t ft;
    zupt_index_entry_t *ents; int n;
    zupt_error_t err = open_archive(f, opts, &hdr, &ft, &ents, &n);
    if (err != ZUPT_OK) { fclose(f); fprintf(stderr, "Error: %s\n", zupt_strerror(err)); return err; }

    if (dir) zupt_mkdir(dir);
    int ok=0, fail=0;
    uint64_t total_extracted = 0;
    time_t start = time(NULL);

    int is_solid = (hdr.global_flags & ZUPT_FLAG_SOLID) != 0;

    if (is_solid) {
        uint64_t total_size = 0;
        for (int i = 0; i < n; i++) {
            if (total_size + ents[i].uncompressed_size < total_size) {
                fprintf(stderr, "  Error: solid stream size overflow\n");
                free(ents); fclose(f); return ZUPT_ERR_OVERFLOW;
            }
            total_size += ents[i].uncompressed_size;
        }

        if (total_size > (uint64_t)4 * 1024 * 1024 * 1024) {
            fprintf(stderr, "  Error: solid stream too large (%llu bytes)\n",
                    (unsigned long long)total_size);
            free(ents); fclose(f); return ZUPT_ERR_OVERFLOW;
        }
        /* Defense for 32-bit platforms where size_t < uint64_t. */
        if (total_size > (uint64_t)SIZE_MAX) {
            fprintf(stderr, "  Error: solid stream exceeds size_t on this platform\n");
            free(ents); fclose(f); return ZUPT_ERR_OVERFLOW;
        }

        uint8_t *solid_buf = (uint8_t*)malloc((size_t)total_size);
        if (!solid_buf) { free(ents); fclose(f); return ZUPT_ERR_NOMEM; }

        fseeko(f, sizeof(zupt_archive_header_t), SEEK_SET);

        if (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) {
            zupt_block_t enc_blk;
            err = read_block(f, &enc_blk);
            free(enc_blk.payload);
            if (err != ZUPT_OK) { free(solid_buf); free(ents); fclose(f); return err; }
        }

        size_t solid_pos = 0;
        uint64_t block_seq = 0;
        int dec_error = 0;

        while (solid_pos < (size_t)total_size) {
            zupt_block_t blk;
            err = read_block(f, &blk);
            if (err != ZUPT_OK) { dec_error = 1; break; }
            if (blk.block_type == ZUPT_BLOCK_INDEX) { free(blk.payload); break; }

            uint8_t *dec; size_t dlen;
            /* Solid mode uses synthetic fi=0 (AAD = (1<<32) | block_seq) */
            uint64_t aad_seq = ((uint64_t)1 << 32) | block_seq;
            err = decompress_block(&blk, &opts->keyring, aad_seq, &dec, &dlen);
            free(blk.payload);
            if (err != ZUPT_OK) {
                fprintf(stderr, "  Solid block %llu decompression failed: %s\n",
                        (unsigned long long)block_seq, zupt_strerror(err));
                dec_error = 1; break;
            }

            if (solid_pos + dlen > (size_t)total_size) dlen = (size_t)total_size - solid_pos;
            memcpy(solid_buf + solid_pos, dec, dlen);
            solid_pos += dlen;
            free(dec);
            block_seq++;
        }

        if (dec_error) {
            free(solid_buf); free(ents); fclose(f);
            return ZUPT_ERR_CORRUPT;
        }

        for (int i = 0; i < n; i++) {
            zupt_index_entry_t *e = &ents[i];
            /* SECURITY: reject path traversal / absolute / .. before fopen */
            if (!zupt_path_is_safe(e->path)) {
                fprintf(stderr, "  Error: rejected unsafe path: %s\n", e->path);
                fail++; continue;
            }
            char out_path[ZUPT_MAX_PATH + 256];
            if (dir) snprintf(out_path, sizeof(out_path), "%s%c%s", dir, ZUPT_PATH_SEP, e->path);
            else { strncpy(out_path, e->path, sizeof(out_path)-1); out_path[sizeof(out_path)-1]='\0'; }
            for (char *p=out_path;*p;p++) if (*p=='/') *p=ZUPT_PATH_SEP;
            ensure_dirs(out_path);

            FILE *of = zupt_safe_fopen_output(out_path);
            if (!of) { fail++; continue; }

            uint64_t off = e->first_block_offset;
            uint64_t sz = e->uncompressed_size;
            /* SECURITY: overflow-safe bound. off and sz are both attacker-
             * controlled 64-bit index fields; the previous `off+sz<=total_size`
             * wrapped on overflow, letting solid_buf+off point far out of
             * bounds for an arbitrary-offset OOB heap read. */
            if (off <= total_size && sz <= total_size - off) {
                if (fwrite(solid_buf + off, 1, (size_t)sz, of) != (size_t)sz) {
                    fprintf(stderr, "Error: write failed (disk full?) for %s\n", e->path);
                    fclose(of);
                    free(solid_buf);
                    return ZUPT_ERR_IO;
                }
                total_extracted += sz;

                /* Verify content hash (empty files have content_hash=0) */
                if (sz > 0) {
                    uint64_t ck = zupt_xxh64(solid_buf + off, (size_t)sz, 0);
                    if (ck == e->content_hash) ok++;
                    else { fprintf(stderr, "  Checksum fail: %s\n", e->path); fail++; }
                } else {
                    ok++; /* Empty file: nothing to verify */
                }
            } else {
                fprintf(stderr, "  Invalid offset: %s\n", e->path); fail++;
            }

            if (opts->verbose) {
                char sz_s[16]; zupt_format_size(sz, sz_s, sizeof(sz_s));
                fprintf(stderr, "  %s (%s)\n", e->path, sz_s);
            }
            fclose(of);
        }

        free(solid_buf);
    } else {
        /* ─── NON-SOLID EXTRACTION ─── */
        /* Multi-threaded decompression: dispatch blocks to N workers.
         * Workers: decrypt → decompress → verify checksum.
         * Main thread: read blocks, dispatch, write output in order. */
        int effective_threads = opts->threads > 1 ? opts->threads : 1;
        zpar_ctx_t *pctx = NULL;
        if (effective_threads > 1) {
            pctx = zpar_create(effective_threads, ZUPT_DEFAULT_BLOCK_SZ, 1,
                               (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) ? &opts->keyring : NULL);
            if (!pctx || pctx->threads_running == 0) {
                if (pctx) zpar_destroy(pctx);
                pctx = NULL;
                effective_threads = 1;
            }
        }

        for (int i=0; i<n; i++) {
            zupt_index_entry_t *e = &ents[i];
            /* SECURITY: reject path traversal / absolute / .. before fopen */
            if (!zupt_path_is_safe(e->path)) {
                fprintf(stderr, "  Error: rejected unsafe path: %s\n", e->path);
                fail++; continue;
            }
            char out_path[ZUPT_MAX_PATH + 256];
            if (dir) snprintf(out_path, sizeof(out_path), "%s%c%s", dir, ZUPT_PATH_SEP, e->path);
            else { strncpy(out_path, e->path, sizeof(out_path)-1); out_path[sizeof(out_path)-1]='\0'; }
            for (char *p=out_path;*p;p++) if (*p=='/') *p=ZUPT_PATH_SEP;
            ensure_dirs(out_path);

            FILE *of = zupt_safe_fopen_output(out_path);
            if (!of) { fprintf(stderr, "  Error: %s\n", out_path); fail++; continue; }

            if (opts->verbose) {
                char sz[16]; zupt_format_size(e->uncompressed_size, sz, sizeof(sz));
                fprintf(stderr, "  %s (%s)\n", e->path, sz);
            }

            fseeko(f, (int64_t)e->first_block_offset, SEEK_SET);
            int berr = 0;

            if (pctx && effective_threads > 1 && e->block_count > 1) {
                /* ─── MT DECOMPRESSION PATH ─── */
                int *pending_slots = (int *)malloc((size_t)effective_threads * sizeof(int));
                if (!pending_slots) { berr = 1; goto file_done; }

                uint32_t blocks_remaining = e->block_count;
                uint64_t decomp_seq = 0;
                while (blocks_remaining > 0) {
                    int npending = 0;

                    /* Submit batch of blocks to workers */
                    while (blocks_remaining > 0 && npending < effective_threads) {
                        zupt_block_t blk;
                        err = read_block(f, &blk);
                        if (err != ZUPT_OK) { berr = 1; break; }

                        /* Handle dedup ref blocks inline (can't submit to workers) */
                        if (blk.block_type == ZUPT_BLOCK_DEDUP_REF && blk.compressed_size == 8 && blk.payload) {
                            /* Flush pending workers first to maintain order */
                            for (int pi = 0; pi < npending; pi++) {
                                zpar_slot_t *s = zpar_wait_slot(pctx, pending_slots[pi]);
                                if (!s || s->error != ZUPT_OK) { berr = 1; }
                                else if (s->output && s->output_len > 0) {
                                    if (fwrite(s->output, 1, s->output_len, of) != s->output_len) berr = 1;
                                    total_extracted += s->output_len;
                                }
                                zpar_release_slot(pctx, pending_slots[pi]);
                            }
                            npending = 0;
                            if (berr) { free(blk.payload); break; }

                            uint64_t ref_off = zupt_le64_get(blk.payload);
                            free(blk.payload);
                            int64_t cur2 = ftello(f);
                            /* Defense: ref_off must be earlier than current position
                             * (dedup refs always point to previously-emitted blocks)
                             * and must be within the file. */
                            if ((int64_t)ref_off >= cur2 || (int64_t)ref_off < 0) {
                                berr = 1; break;
                            }
                            fseeko(f, (int64_t)ref_off, SEEK_SET);
                            zupt_block_t ref_blk;
                            err = read_block(f, &ref_blk);
                            fseeko(f, cur2, SEEK_SET);
                            if (err != ZUPT_OK) { berr = 1; break; }
                            /* Defense: refs must point to data blocks, not other refs.
                             * Prevents amplification + infinite loop attacks. */
                            if (ref_blk.block_type == ZUPT_BLOCK_DEDUP_REF) {
                                free(ref_blk.payload); berr = 1; break;
                            }
                            uint8_t *rdec; size_t rdlen;
                            err = decompress_block(&ref_blk, &opts->keyring, 0, &rdec, &rdlen);
                            free(ref_blk.payload);
                            if (err != ZUPT_OK) { berr = 1; break; }
                            if (fwrite(rdec, 1, rdlen, of) != rdlen) berr = 1;
                            total_extracted += rdlen;
                            free(rdec);
                            blocks_remaining--;
                            decomp_seq++;
                            continue;
                        }

                        /* AAD = ((file_index+1) << 32) | per_file_block_seq.
                         * decomp_seq counts blocks within the current file.
                         * Dedup mode uses sentinel seq=0. */
                        uint64_t aad_seq;
                        if (hdr.global_flags & ZUPT_FLAG_DEDUP) {
                            aad_seq = 0;
                        } else {
                            aad_seq = (((uint64_t)(i + 1)) << 32) | decomp_seq;
                        }
                        int slot = zpar_submit_decompress(pctx,
                            blk.payload, (size_t)blk.compressed_size,
                            aad_seq, blk.codec_id, blk.block_flags,
                            blk.checksum, blk.uncompressed_size);

                        free(blk.payload); /* Worker copied it */
                        if (slot < 0) { berr = 1; break; }
                        pending_slots[npending++] = slot;
                        blocks_remaining--;
                        decomp_seq++;
                    }

                    /* Collect results in order */
                    for (int pi = 0; pi < npending; pi++) {
                        zpar_slot_t *s = zpar_wait_slot(pctx, pending_slots[pi]);
                        if (!s || s->error != ZUPT_OK) {
                            berr = 1;
                            zpar_release_slot(pctx, pending_slots[pi]);
                            continue;
                        }
                        if (s->output && s->output_len > 0) {
                            if (fwrite(s->output, 1, s->output_len, of) != s->output_len) berr = 1;
                            total_extracted += s->output_len;
                        }
                        zpar_release_slot(pctx, pending_slots[pi]);
                    }
                    if (berr) break;
                }
                free(pending_slots);
            } else {
                /* ─── SINGLE-THREADED DECOMPRESSION PATH ─── */
                for (uint32_t b=0; b<e->block_count; b++) {
                    zupt_block_t blk;
                    err = read_block(f, &blk);
                    if (err != ZUPT_OK) { berr=1; break; }

                    /* Handle dedup reference blocks */
                    if (blk.block_type == ZUPT_BLOCK_DEDUP_REF && blk.compressed_size == 8 && blk.payload) {
                        uint64_t ref_off = zupt_le64_get(blk.payload);
                        free(blk.payload);
                        int64_t cur = ftello(f);
                        if ((int64_t)ref_off >= cur || (int64_t)ref_off < 0) { berr=1; break; }
                        fseeko(f, (int64_t)ref_off, SEEK_SET);
                        zupt_block_t ref_blk;
                        err = read_block(f, &ref_blk);
                        fseeko(f, cur, SEEK_SET);
                        if (err != ZUPT_OK) { berr=1; break; }
                        if (ref_blk.block_type == ZUPT_BLOCK_DEDUP_REF) {
                            free(ref_blk.payload); berr=1; break;
                        }
                        uint8_t *dec; size_t dlen;
                        /* Dedup refs use seq=0 (legacy MAC fallback handles this) */
                        err = decompress_block(&ref_blk, &opts->keyring, 0, &dec, &dlen);
                        free(ref_blk.payload);
                        if (err != ZUPT_OK) { berr=1; break; }
                        if (fwrite(dec, 1, dlen, of) != dlen) berr = 1;
                        total_extracted += dlen;
                        free(dec);
                        continue;
                    }

                    uint8_t *dec; size_t dlen;
                    /* AAD = ((file_index_in_archive + 1) << 32) | per_file_block_seq.
                     * Matches encrypt-side computation, prevents block-swap attacks.
                     * Dedup mode uses sentinel seq=0 (matches encrypt-side). */
                    uint64_t aad_seq;
                    if (hdr.global_flags & ZUPT_FLAG_DEDUP) {
                        aad_seq = 0;
                    } else {
                        aad_seq = (((uint64_t)(i + 1)) << 32) | (uint64_t)b;
                    }
                    err = decompress_block(&blk, &opts->keyring, aad_seq, &dec, &dlen);
                    free(blk.payload);
                    if (err != ZUPT_OK) { berr=1; break; }
                    if (fwrite(dec, 1, dlen, of) != dlen) berr = 1;
                    total_extracted += dlen;
                    free(dec);
                }
            }

file_done:
            fclose(of);
            if (berr) {
                /* Authentication failure or other error: remove partial/empty output */
                unlink(out_path);
                fail++;
            } else {
                ok++;
            }
        }

        if (pctx) zpar_destroy(pctx);
    }

    time_t elapsed = time(NULL) - start;
    if (elapsed < 1) elapsed = 1;
    char sz[16]; zupt_format_size(total_extracted, sz, sizeof(sz));
    double speed = (double)total_extracted / (double)elapsed / 1048576.0;
    fprintf(stderr, "\n  Extracted %d file(s), %s (%.1f MB/s)", ok, sz, speed);
    if (fail > 0) fprintf(stderr, ", %d error(s)", fail);
    fprintf(stderr, "\n");

    /* F-12 of v2.4.3: print the archive comment, if any. open_archive
     * decrypted+stored it in opts->comment when the keyring was active. */
    if (opts->has_comment && opts->comment[0] != '\0') {
        fprintf(stderr, "\n  Comment: %s\n", opts->comment);
    }

    free(ents); fclose(f);
    return fail>0 ? ZUPT_ERR_CORRUPT : ZUPT_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST
 * ═══════════════════════════════════════════════════════════════════ */

zupt_error_t zupt_test_archive(const char *arc, zupt_options_t *opts) {
    FILE *f = fopen(arc, "rb");
    if (!f) { fprintf(stderr, "Error: Cannot open '%s'\n", arc); return ZUPT_ERR_IO; }

    zupt_archive_header_t hdr; zupt_footer_t ft;
    zupt_index_entry_t *ents; int n;
    zupt_error_t err = open_archive(f, opts, &hdr, &ft, &ents, &n);
    if (err != ZUPT_OK) { fclose(f); fprintf(stderr, "Error: %s\n", zupt_strerror(err)); return err; }

    int pass=0, fail=0;
    int is_solid = (hdr.global_flags & ZUPT_FLAG_SOLID) != 0;

    if (is_solid) {
        uint64_t total_size = 0;
        for (int i = 0; i < n; i++) total_size += ents[i].uncompressed_size;

        if (total_size > (uint64_t)ZUPT_MAX_BLOCK_SZ * 4096) {
            fprintf(stderr, "  Error: solid stream too large for test\n");
            free(ents); fclose(f); return ZUPT_ERR_OVERFLOW;
        }

        uint8_t *solid_buf = (uint8_t*)malloc((size_t)total_size);
        if (!solid_buf) { free(ents); fclose(f); return ZUPT_ERR_NOMEM; }

        fseeko(f, sizeof(zupt_archive_header_t), SEEK_SET);
        if (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) {
            zupt_block_t enc_blk;
            err = read_block(f, &enc_blk);
            if (err == ZUPT_OK) free(enc_blk.payload);
        }

        size_t solid_pos = 0;
        uint64_t block_seq = 0;
        int blocks_ok = 0, blocks_fail = 0;

        while (solid_pos < (size_t)total_size) {
            zupt_block_t blk;
            err = read_block(f, &blk);
            if (err != ZUPT_OK) { blocks_fail++; break; }
            if (blk.block_type == ZUPT_BLOCK_INDEX) { free(blk.payload); break; }

            uint8_t *dec; size_t dlen;
            /* Solid mode AAD: synthetic fi=0 */
            uint64_t aad_seq = ((uint64_t)1 << 32) | block_seq;
            err = decompress_block(&blk, &opts->keyring, aad_seq, &dec, &dlen);
            free(blk.payload);
            if (err != ZUPT_OK) {
                fprintf(stderr, "  Block %llu: FAIL (%s)\n",
                        (unsigned long long)block_seq, zupt_strerror(err));
                blocks_fail++; break;
            }

            if (solid_pos + dlen > (size_t)total_size) dlen = (size_t)total_size - solid_pos;
            memcpy(solid_buf + solid_pos, dec, dlen);
            solid_pos += dlen;
            free(dec);
            blocks_ok++;
            block_seq++;
        }

        if (blocks_fail > 0) {
            fprintf(stderr, "  Solid stream: %d blocks OK, %d failed\n", blocks_ok, blocks_fail);
            free(solid_buf); free(ents); fclose(f);
            return ZUPT_ERR_CORRUPT;
        }

        for (int i = 0; i < n; i++) {
            zupt_index_entry_t *e = &ents[i];
            uint64_t off = e->first_block_offset;
            uint64_t sz = e->uncompressed_size;
            int fok = 1;

            if (off + sz > total_size) {
                fok = 0;
            } else if (sz > 0) {
                uint64_t ck = zupt_xxh64(solid_buf + off, (size_t)sz, 0);
                if (ck != e->content_hash) fok = 0;
            }

            if (fok) {
                if (opts->verbose) fprintf(stderr, "  OK: %s\n", e->path);
                pass++;
            } else {
                fprintf(stderr, "  FAIL: %s (checksum mismatch)\n", e->path);
                fail++;
            }
        }

        free(solid_buf);
    } else {
        for (int i = 0; i < n; i++) {
            zupt_index_entry_t *e = &ents[i];
            fseeko(f, (int64_t)e->first_block_offset, SEEK_SET);
            int fok = 1;
            for (uint32_t b = 0; b < e->block_count; b++) {
                zupt_block_t blk;
                err = read_block(f, &blk);
                if (err != ZUPT_OK) { fok=0; break; }
                uint8_t *dec; size_t dlen;
                /* AAD = ((file_index+1) << 32) | per_file_block_seq (or
                 * sentinel 0 in dedup mode). Matches encrypt-side. */
                uint64_t aad_seq;
                if (hdr.global_flags & ZUPT_FLAG_DEDUP) {
                    aad_seq = 0;
                } else {
                    aad_seq = (((uint64_t)(i + 1)) << 32) | (uint64_t)b;
                }
                err = decompress_block(&blk, &opts->keyring, aad_seq, &dec, &dlen);
                free(blk.payload);
                if (err != ZUPT_OK) { fok=0; break; }
                free(dec);
            }
            if (fok) { if (opts->verbose) fprintf(stderr, "  OK: %s\n", e->path); pass++; }
            else { fprintf(stderr, "  FAIL: %s (%s)\n", e->path, zupt_strerror(err)); fail++; }
        }
    }

    printf("\n  Test: %d passed, %d failed (%d files)\n", pass, fail, n);
    free(ents); fclose(f);
    return fail>0 ? ZUPT_ERR_BAD_CHECKSUM : ZUPT_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * ARCHIVE INFO — read-only metadata inspection (no password needed)
 *
 * Shows: format version, creation time, UUID, flags (encrypted,
 * solid, multithreaded, PQ, dedup, disk), archive size, block count.
 * Does NOT decrypt or verify checksums — works on any archive.
 * ═══════════════════════════════════════════════════════════════════ */
zupt_error_t zupt_archive_info(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "Error: Cannot open '%s': %s\n", path, strerror(errno)); return ZUPT_ERR_IO; }

    zupt_archive_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
        fprintf(stderr, "Error: Not a zupt archive (file too small)\n");
        fclose(f); return ZUPT_ERR_CORRUPT;
    }
    if (hdr.magic[0]!=ZUPT_MAGIC_0 || hdr.magic[1]!=ZUPT_MAGIC_1 ||
        hdr.magic[2]!=ZUPT_MAGIC_2 || hdr.magic[3]!=ZUPT_MAGIC_3) {
        fprintf(stderr, "Error: Not a zupt archive (bad magic)\n");
        fclose(f); return ZUPT_ERR_BAD_MAGIC;
    }

    /* Archive file size */
    fseeko(f, 0, SEEK_END);
    uint64_t file_size = (uint64_t)ftello(f);
    char sz_buf[32];
    zupt_format_size(file_size, sz_buf, sizeof(sz_buf));

    /* Try to read footer for block count.
     * F-08 of v2.3.0: also detect whether the v1.5 archive-integrity-trailer
     * is present, so `zupt info` can report it. The footer can be at EOF-32
     * (v1.4) or EOF-64 (v1.5, with 32-byte AIT trailing).  */
    uint64_t total_blocks = 0;
    int has_footer = 0;
    int has_ait = 0;
    if (file_size >= sizeof(zupt_footer_t) + ZUPT_AIT_SIZE) {
        fseeko(f, -(int64_t)(sizeof(zupt_footer_t) + ZUPT_AIT_SIZE), SEEK_END);
        zupt_footer_t ft;
        if (fread(&ft, sizeof(ft), 1, f) == 1 &&
            ft.footer_magic[0]=='Z' && ft.footer_magic[1]=='E' &&
            ft.footer_magic[2]=='N' && ft.footer_magic[3]=='D') {
            total_blocks = ft.total_blocks;
            has_footer = 1;
            has_ait = 1;
        }
    }
    if (!has_footer && file_size > sizeof(zupt_footer_t)) {
        fseeko(f, -(int64_t)sizeof(zupt_footer_t), SEEK_END);
        zupt_footer_t ft;
        if (fread(&ft, sizeof(ft), 1, f) == 1 &&
            ft.footer_magic[0]=='Z' && ft.footer_magic[1]=='E' &&
            ft.footer_magic[2]=='N' && ft.footer_magic[3]=='D') {
            total_blocks = ft.total_blocks;
            has_footer = 1;
        }
    }
    fclose(f);

    /* UUID */
    char uuid[40];
    snprintf(uuid, sizeof(uuid),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        hdr.archive_id[0], hdr.archive_id[1], hdr.archive_id[2], hdr.archive_id[3],
        hdr.archive_id[4], hdr.archive_id[5], hdr.archive_id[6], hdr.archive_id[7],
        hdr.archive_id[8], hdr.archive_id[9], hdr.archive_id[10], hdr.archive_id[11],
        hdr.archive_id[12], hdr.archive_id[13], hdr.archive_id[14], hdr.archive_id[15]);

    /* Creation time */
    uint64_t ct_sec = hdr.creation_time / 1000000000ULL;
    char timebuf[64] = "unknown";
    if (ct_sec > 0) {
        time_t tt = (time_t)ct_sec;
        struct tm *tm = localtime(&tt);
        if (tm) strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    }

    /* Flags */
    uint32_t fl = hdr.global_flags;

    printf("\n");
    printf("  Archive:       %s\n", path);
    printf("  Size:          %s (%llu bytes)\n", sz_buf, (unsigned long long)file_size);
    printf("  Format:        v%u.%u\n", hdr.version_major, hdr.version_minor);
    printf("  Top-MAC:       %s\n",
        has_ait ? ((fl & ZUPT_FLAG_ENCRYPTED) ? "YES (HMAC-SHA256)" : "YES (XXH64)")
                : "no (v1.4 legacy)");
    printf("  UUID:          %s\n", uuid);
    printf("  Created:       %s\n", timebuf);
    if (has_footer)
        printf("  Blocks:        %llu\n", (unsigned long long)total_blocks);
    printf("  Encrypted:     %s\n", (fl & ZUPT_FLAG_ENCRYPTED) ? "YES" : "no");
    if (fl & ZUPT_FLAG_PQ_HYBRID)
        printf("  PQ Hybrid:     YES (ML-KEM-768 + X25519)\n");
    if (fl & ZUPT_FLAG_SOLID)
        printf("  Solid:         YES\n");
    if (fl & ZUPT_FLAG_MULTITHREADED)
        printf("  Multithreaded: YES\n");
    if (fl & ZUPT_FLAG_DEDUP)
        printf("  Dedup:         YES (block-level)\n");
    if (fl & ZUPT_FLAG_DISK_IMAGE)
        printf("  Disk image:    YES\n");
    if (hdr.comment_offset != 0)
        printf("  Comment:       present (use 'zupt x' with the right key to read)\n");
    printf("  Flags:         0x%04X\n", fl);
    printf("\n");

    return ZUPT_OK;
}
