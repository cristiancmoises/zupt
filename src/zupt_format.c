/*
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

#ifdef _WIN32
  #include <io.h>
  #define fseeko _fseeki64
  #define ftello _ftelli64
#endif

/* ═══════════════════════════════════════════════════════════════════
 * UTILITY
 * ═══════════════════════════════════════════════════════════════════ */

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
    while(n<(int)blen&&n<9){uint64_t x=b[n];*v|=(x&0x7F)<<s;n++;if(!(x&0x80))return n;s+=7;}
    return -1;
}
int zupt_write_varint(FILE *f, uint64_t v) {
    uint8_t b[10]; int n=zupt_encode_varint(b,v); return fwrite(b,1,(size_t)n,f)==(size_t)n?n:-1;
}
int zupt_read_varint(FILE *f, uint64_t *v) {
    *v=0; int s=0;
    for(int i=0;i<9;i++){int c=fgetc(f);if(c==EOF)return -1;
    *v|=(uint64_t)(c&0x7F)<<s;if(!(c&0x80))return i+1;s+=7;} return -1;
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
        char **new_paths = (char**)realloc(fl->paths, (size_t)new_cap * sizeof(char*));
        char **new_arcs  = (char**)realloc(fl->arc_paths, (size_t)new_cap * sizeof(char*));
        if (!new_paths || !new_arcs) {
            /* OOM: keep existing pointers intact, skip this file */
            if (new_paths && new_paths != fl->paths) free(new_paths);
            if (new_arcs && new_arcs != fl->arc_paths) free(new_arcs);
            fprintf(stderr, "  Warning: out of memory adding '%s'\n", disk);
            return;
        }
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

static int w8(FILE*f,uint8_t v){return fwrite(&v,1,1,f)==1?0:-1;}
static int w16le(FILE*f,uint16_t v){uint8_t b[2];zupt_le16_put(b,v);return fwrite(b,1,2,f)==2?0:-1;}
static int w64le(FILE*f,uint64_t v){uint8_t b[8];zupt_le64_put(b,v);return fwrite(b,1,8,f)==8?0:-1;}
static int r16le(FILE*f,uint16_t*v){uint8_t b[2];if(fread(b,1,2,f)!=2)return -1;*v=zupt_le16_get(b);return 0;}
static int r64le(FILE*f,uint64_t*v){uint8_t b[8];if(fread(b,1,8,f)!=8)return -1;*v=zupt_le64_get(b);return 0;}

static void ensure_dirs(const char *path) {
    char tmp[ZUPT_MAX_PATH]; strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
    for (char *p=tmp+1;*p;p++)
        if (*p=='/'||*p=='\\') { *p='\0'; zupt_mkdir(tmp); *p=ZUPT_PATH_SEP; }
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
    if (opts->encrypt) hdr.global_flags |= ZUPT_FLAG_ENCRYPTED;
    if (opts->threads > 1) hdr.global_flags |= ZUPT_FLAG_MULTITHREADED;
    hdr.creation_time = now_ns();
    gen_uuid(hdr.archive_id);
    if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) write_err = 1;

    if (opts->encrypt) {
        hdr.encryption_header_off = safe_ftello(out);

        if (opts->pq_mode) {
            /* ─── PQ HYBRID MODE ─── */
            if (hdr.global_flags & ZUPT_FLAG_PQ_HYBRID) {} /* already set */
            hdr.global_flags |= ZUPT_FLAG_PQ_HYBRID;

            uint8_t enc_hdr_buf[1200]; /* enc_type(1) + ct(1088) + eph_pk(32) + nonce(16) = 1137 */
            size_t enc_hdr_len = 0;
            if (!opts->quiet) fprintf(stderr, "  Post-quantum key encapsulation (ML-KEM-768 + X25519)...\n");
            if (zupt_hybrid_encrypt_init(&opts->keyring, opts->keyfile, enc_hdr_buf, &enc_hdr_len) != 0) {
                fprintf(stderr, "Error: PQ hybrid key encapsulation failed.\n");
                fclose(out); return ZUPT_ERR_AUTH_FAIL;
            }

            w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
            w8(out, ZUPT_BLOCK_ENC_HEADER);
            w16le(out, ZUPT_CODEC_STORE); w16le(out, 0);
            zupt_write_varint(out, enc_hdr_len); zupt_write_varint(out, enc_hdr_len);
            w64le(out, zupt_xxh64(enc_hdr_buf, enc_hdr_len, 0));
            if (fwrite(enc_hdr_buf, 1, enc_hdr_len, out) != enc_hdr_len) write_err = 1;

            fseeko(out, 0, SEEK_SET);
            if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) write_err = 1;
            fseeko(out, 0, SEEK_END);

            if (!opts->quiet) fprintf(stderr, "  Encryption: PQ Hybrid (ML-KEM-768 + X25519) + AES-256-CTR + HMAC-SHA256\n\n");
        } else {
            /* ─── PASSWORD MODE (PBKDF2, unchanged from v0.5.1) ─── */
            uint8_t salt[ZUPT_SALT_SIZE], nonce[ZUPT_NONCE_SIZE];
            zupt_random_bytes(salt, ZUPT_SALT_SIZE);
            zupt_random_bytes(nonce, ZUPT_NONCE_SIZE);

            if (!opts->quiet) fprintf(stderr, "  Deriving encryption key (PBKDF2-SHA256, %d iterations)...\n", ZUPT_KDF_ITERATIONS);
            zupt_derive_keys(&opts->keyring, opts->password, salt, nonce, ZUPT_KDF_ITERATIONS);

            /* enc_type prefix for backward compat detection */
            uint8_t enc_hdr[53]; /* enc_type(1) + salt(32) + nonce(16) + iter(4) */
            enc_hdr[0] = ZUPT_ENC_PBKDF2;
            memcpy(enc_hdr + 1, salt, 32);
            memcpy(enc_hdr + 33, nonce, 16);
            uint32_t iter = ZUPT_KDF_ITERATIONS;
            memcpy(enc_hdr + 49, &iter, 4);

            w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
            w8(out, ZUPT_BLOCK_ENC_HEADER);
            w16le(out, ZUPT_CODEC_STORE); w16le(out, 0);
            zupt_write_varint(out, 53); zupt_write_varint(out, 53);
            w64le(out, zupt_xxh64(enc_hdr, 53, 0));
            if (fwrite(enc_hdr, 1, 53, out) != 53) write_err = 1;

            fseeko(out, 0, SEEK_SET);
            if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) write_err = 1;
            fseeko(out, 0, SEEK_END);

            if (!opts->quiet) fprintf(stderr, "  Encryption: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC)\n\n");
        }
    }

    zupt_index_entry_t *index = (zupt_index_entry_t*)calloc((size_t)num_files, sizeof(zupt_index_entry_t));
    uint8_t *rbuf = (uint8_t*)malloc(opts->block_size);
    uint8_t *cbuf = (uint8_t*)malloc(zupt_lzh_bound(opts->block_size) + 512);
    if (!index || !rbuf || !cbuf) { free(index); free(rbuf); free(cbuf); fclose(out); return ZUPT_ERR_NOMEM; }

    uint64_t total_blocks = 0, total_in = 0, total_out = 0;
    uint64_t block_seq = 0;
    time_t start_time = time(NULL);

    /* Create parallel context if multi-threaded */
    zpar_ctx_t *pctx = NULL;
    int effective_threads = opts->threads > 1 ? opts->threads : 1;
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

                    int slot = zpar_submit_compress(pctx, rbuf, nread,
                                                     block_seq, opts->level, opts->codec_id);
                    if (slot < 0) { write_err = 1; break; }
                    pending_slots[npending] = slot;
                    pending_seqs[npending] = block_seq;
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
                enc_payload = zupt_encrypt_buffer(&opts->keyring, payload, payload_size, block_seq, &enc_len);
                if (!enc_payload) { fclose(inf); free(index); free(rbuf); free(cbuf); fclose(out); return ZUPT_ERR_NOMEM; }
                payload = enc_payload;
                payload_size = enc_len;
                bflags |= ZUPT_BFLAG_ENCRYPTED;
            }

            w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
            w8(out, ZUPT_BLOCK_DATA);
            w16le(out, codec); w16le(out, bflags);
            zupt_write_varint(out, (uint64_t)nread);
            zupt_write_varint(out, payload_size);
            w64le(out, checksum);
            if (fwrite(payload, 1, (size_t)payload_size, out) != (size_t)payload_size) write_err = 1;

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

    uint8_t *enc_idx = NULL;
    uint16_t idx_bflags = 0;
    if (opts->encrypt && opts->keyring.active) {
        size_t enc_len;
        enc_idx = zupt_encrypt_buffer(&opts->keyring, ic_pay, ic_plen, block_seq, &enc_len);
        ic_pay = enc_idx; ic_plen = enc_len;
        idx_bflags |= ZUPT_BFLAG_ENCRYPTED;
    }

    uint64_t ic_ck = zupt_xxh64(ibuf, ip, 0);
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
        fprintf(stderr, "  Speed:        %.1f MB/s (%llds)\n", speed, (long long)elapsed);
    }

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
    if (opts->encrypt) hdr.global_flags |= ZUPT_FLAG_ENCRYPTED;
    hdr.creation_time = now_ns();
    gen_uuid(hdr.archive_id);
    if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) write_err = 1;

    if (opts->encrypt) {
        hdr.encryption_header_off = safe_ftello(out);
        uint8_t salt[ZUPT_SALT_SIZE], nonce[ZUPT_NONCE_SIZE];
        zupt_random_bytes(salt, ZUPT_SALT_SIZE);
        zupt_random_bytes(nonce, ZUPT_NONCE_SIZE);
        if (!opts->quiet) fprintf(stderr, "  Deriving encryption key...\n");
        zupt_derive_keys(&opts->keyring, opts->password, salt, nonce, ZUPT_KDF_ITERATIONS);
        uint8_t enc_hdr[52];
        memcpy(enc_hdr, salt, 32); memcpy(enc_hdr+32, nonce, 16);
        uint32_t iter = ZUPT_KDF_ITERATIONS; memcpy(enc_hdr+48, &iter, 4);
        w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
        w8(out, ZUPT_BLOCK_ENC_HEADER);
        w16le(out, ZUPT_CODEC_STORE); w16le(out, 0);
        zupt_write_varint(out, 52); zupt_write_varint(out, 52);
        w64le(out, zupt_xxh64(enc_hdr, 52, 0));
        if (fwrite(enc_hdr, 1, 52, out) != 52) write_err = 1;
        fseeko(out, 0, SEEK_SET);
        if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) write_err = 1;
        fseeko(out, 0, SEEK_END);
        if (!opts->quiet) fprintf(stderr, "  Encryption: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC)\n\n");
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
            enc_pay = zupt_encrypt_buffer(&opts->keyring, payload, payload_size, block_seq, &enc_len);
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

    uint8_t *enc_idx = NULL; uint16_t idx_bflags = 0;
    if (opts->encrypt && opts->keyring.active) {
        size_t enc_len;
        enc_idx = zupt_encrypt_buffer(&opts->keyring, ic_pay, ic_plen, block_seq, &enc_len);
        if (enc_idx) { ic_pay = enc_idx; ic_plen = enc_len; idx_bflags |= ZUPT_BFLAG_ENCRYPTED; }
    }

    w8(out, ZUPT_BLOCK_MAGIC_0); w8(out, ZUPT_BLOCK_MAGIC_1);
    w8(out, ZUPT_BLOCK_INDEX);
    w16le(out, ic_codec); w16le(out, idx_bflags);
    zupt_write_varint(out, (uint64_t)ip);
    zupt_write_varint(out, ic_plen);
    w64le(out, zupt_xxh64(ibuf, ip, 0));
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

static zupt_error_t read_footer(FILE *f, zupt_footer_t *ft) {
    fseeko(f, -(int64_t)sizeof(zupt_footer_t), SEEK_END);
    if (fread(ft, sizeof(*ft), 1, f) != 1) return ZUPT_ERR_IO;
    if (ft->footer_magic[0]!='Z'||ft->footer_magic[1]!='E'||
        ft->footer_magic[2]!='N'||ft->footer_magic[3]!='D') return ZUPT_ERR_CORRUPT;
    return ZUPT_OK;
}

static zupt_error_t read_block(FILE *f, zupt_block_t *b) {
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

static zupt_error_t decompress_block(const zupt_block_t *b, const zupt_keyring_t *kr,
                                      uint64_t block_seq, uint8_t **out, size_t *olen) {
    const uint8_t *comp_data = b->payload;
    size_t comp_len = (size_t)b->compressed_size;
    uint8_t *dec_payload = NULL;

    if (!b->payload && comp_len > 0) return ZUPT_ERR_CORRUPT;
    if (b->uncompressed_size > ZUPT_MAX_BLOCK_SZ) return ZUPT_ERR_OVERFLOW;
    if (comp_len > ZUPT_MAX_BLOCK_SZ + 1024) return ZUPT_ERR_OVERFLOW;

    if (b->block_flags & ZUPT_BFLAG_ENCRYPTED) {
        if (!kr || !kr->active) return ZUPT_ERR_AUTH_FAIL;
        size_t dec_len;
        dec_payload = zupt_decrypt_buffer(kr, comp_data, comp_len, block_seq, &dec_len);
        if (!dec_payload) return ZUPT_ERR_AUTH_FAIL;
        comp_data = dec_payload;
        comp_len = dec_len;
    }

    *olen = (size_t)b->uncompressed_size;
    if (*olen == 0) { *out = NULL; free(dec_payload); return ZUPT_OK; }
    *out = (uint8_t*)malloc(*olen);
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
        int64_t dsz = vvz_decompress(comp_data, comp_len, *out, *olen);
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

static zupt_error_t read_enc_header(FILE *f, zupt_archive_header_t *hdr, zupt_options_t *opts) {
    if (!(hdr->global_flags & ZUPT_FLAG_ENCRYPTED)) return ZUPT_OK;

    fseeko(f, (int64_t)hdr->encryption_header_off, SEEK_SET);
    zupt_block_t eb;
    zupt_error_t err = read_block(f, &eb);
    if (err != ZUPT_OK) return err;

    if (eb.compressed_size < 1) { free(eb.payload); return ZUPT_ERR_CORRUPT; }

    uint8_t enc_type = eb.payload[0];

    if (enc_type == ZUPT_ENC_PQ_HYBRID) {
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
    *n = (int)count;
    *ents = (zupt_index_entry_t*)calloc((size_t)count, sizeof(zupt_index_entry_t));
    if (!*ents) return ZUPT_ERR_NOMEM;

    for (uint64_t i = 0; i < count; i++) {
        zupt_index_entry_t *e = &(*ents)[i];
        uint64_t plen;
        vn = zupt_decode_varint(buf+p, blen-p, &plen);
        if (vn<0||p+(size_t)vn+plen>blen) { free(*ents); return ZUPT_ERR_CORRUPT; }
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
    err = read_footer(f, ft);
    if (err != ZUPT_OK) return err;
    err = read_enc_header(f, hdr, opts);
    if (err != ZUPT_OK) return err;

    fseeko(f, (int64_t)ft->index_offset, SEEK_SET);
    zupt_block_t ib;
    err = read_block(f, &ib);
    if (err != ZUPT_OK) return err;

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
            err = decompress_block(&blk, &opts->keyring, block_seq, &dec, &dlen);
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
            char out_path[ZUPT_MAX_PATH + 256];
            if (dir) snprintf(out_path, sizeof(out_path), "%s%c%s", dir, ZUPT_PATH_SEP, e->path);
            else { strncpy(out_path, e->path, sizeof(out_path)-1); out_path[sizeof(out_path)-1]='\0'; }
            for (char *p=out_path;*p;p++) if (*p=='/') *p=ZUPT_PATH_SEP;
            ensure_dirs(out_path);

            FILE *of = fopen(out_path, "wb");
            if (!of) { fail++; continue; }

            uint64_t off = e->first_block_offset;
            uint64_t sz = e->uncompressed_size;
            if (off + sz <= total_size) {
                fwrite(solid_buf + off, 1, (size_t)sz, of);
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
            char out_path[ZUPT_MAX_PATH + 256];
            if (dir) snprintf(out_path, sizeof(out_path), "%s%c%s", dir, ZUPT_PATH_SEP, e->path);
            else { strncpy(out_path, e->path, sizeof(out_path)-1); out_path[sizeof(out_path)-1]='\0'; }
            for (char *p=out_path;*p;p++) if (*p=='/') *p=ZUPT_PATH_SEP;
            ensure_dirs(out_path);

            FILE *of = fopen(out_path, "wb");
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

                        int slot = zpar_submit_decompress(pctx,
                            blk.payload, (size_t)blk.compressed_size,
                            decomp_seq, blk.codec_id, blk.block_flags,
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
                            fwrite(s->output, 1, s->output_len, of);
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
                    uint8_t *dec; size_t dlen;
                    err = decompress_block(&blk, &opts->keyring, 0, &dec, &dlen);
                    free(blk.payload);
                    if (err != ZUPT_OK) { berr=1; break; }
                    fwrite(dec, 1, dlen, of);
                    total_extracted += dlen;
                    free(dec);
                }
            }

file_done:
            fclose(of);
            if (berr) fail++; else ok++;
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
            err = decompress_block(&blk, &opts->keyring, block_seq, &dec, &dlen);
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
                err = decompress_block(&blk, &opts->keyring, 0, &dec, &dlen);
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
