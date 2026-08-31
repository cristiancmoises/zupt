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
#include "zupt_internal.h"
#include "zupt_cpuid.h"   /* zupt_cpu for AUTO codec detection */
#include "zupt_parallel.h"
#include "vaptvupt.h"  /* VAPTVUPT: VaptVupt codec integration */
#include "vaptvupt_api.h" /* VAPTVUPT: simplified ZUPT integration API */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

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

#ifdef _WIN32
  #include <io.h>
  #include <fcntl.h>
  #include <wchar.h>
  #include <winternl.h>
  #ifndef fseeko
    #define fseeko _fseeki64
  #endif
  #ifndef ftello
    #define ftello _ftelli64
  #endif
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
        case ZUPT_CODEC_ZUPT_LZ: return "ZUPT-LZ";
        case ZUPT_CODEC_ZUPT_LZH: return "ZUPT-LZH";
        case ZUPT_CODEC_ZUPT_LZHP: return "ZUPT-LZHP";
        case ZUPT_CODEC_VAPTVUPT: return "VaptVupt"; /* VAPTVUPT */
        case ZUPT_CODEC_AUTO: return "Auto";
        default: return "Unknown";
    }
}

/* Decode one shortest-form UTF-8 scalar without reading past the terminating
 * NUL. A zero return means invalid UTF-8. */
static size_t zupt_decode_utf8_scalar(const unsigned char *text,
                                      uint32_t *codepoint) {
    unsigned char a = text[0];
    if (a < 0x80u) {
        *codepoint = a;
        return 1;
    }
    if (text[1] == 0) return 0;
    unsigned char b = text[1];
    if (a >= 0xC2u && a <= 0xDFu && (b & 0xC0u) == 0x80u) {
        *codepoint = ((uint32_t)(a & 0x1Fu) << 6) | (uint32_t)(b & 0x3Fu);
        return 2;
    }
    if (text[2] == 0) return 0;
    unsigned char c = text[2];
    if ((c & 0xC0u) != 0x80u) return 0;
    if (((a == 0xE0u && b >= 0xA0u && b <= 0xBFu) ||
         ((a >= 0xE1u && a <= 0xECu) && (b & 0xC0u) == 0x80u) ||
         (a == 0xEDu && b >= 0x80u && b <= 0x9Fu) ||
         ((a >= 0xEEu && a <= 0xEFu) && (b & 0xC0u) == 0x80u))) {
        *codepoint = ((uint32_t)(a & 0x0Fu) << 12) |
                     ((uint32_t)(b & 0x3Fu) << 6) |
                     (uint32_t)(c & 0x3Fu);
        return 3;
    }
    if (text[3] == 0) return 0;
    unsigned char d = text[3];
    if ((d & 0xC0u) != 0x80u) return 0;
    if (!((a == 0xF0u && b >= 0x90u && b <= 0xBFu) ||
          ((a >= 0xF1u && a <= 0xF3u) && (b & 0xC0u) == 0x80u) ||
          (a == 0xF4u && b >= 0x80u && b <= 0x8Fu)))
        return 0;
    *codepoint = ((uint32_t)(a & 0x07u) << 18) |
                 ((uint32_t)(b & 0x3Fu) << 12) |
                 ((uint32_t)(c & 0x3Fu) << 6) |
                 (uint32_t)(d & 0x3Fu);
    return 4;
}

static int zupt_codepoint_is_display_control(uint32_t codepoint) {
    return codepoint < 0x20u ||
           (codepoint >= 0x7Fu && codepoint <= 0x9Fu) ||
           codepoint == 0x061Cu ||
           (codepoint >= 0x200Bu && codepoint <= 0x200Fu) ||
           (codepoint >= 0x2028u && codepoint <= 0x202Eu) ||
           (codepoint >= 0x2060u && codepoint <= 0x206Fu) ||
           codepoint == 0xFEFFu ||
           (codepoint >= 0xFFF9u && codepoint <= 0xFFFBu);
}

/* Archive comments are authenticated data, but authentication says nothing
 * about whether their author is trusted. Escape invalid UTF-8 and actual
 * Unicode control/format scalars before display so an untrusted archive cannot
 * inject forged lines, ANSI/OSC commands, clipboard sequences, or bidi-spoofed
 * diagnostics. Printable UTF-8 is preserved byte-for-byte. */
static void zupt_print_terminal_safe_text(FILE *stream, const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;
    while (*cursor != '\0') {
        uint32_t codepoint = 0;
        size_t length = zupt_decode_utf8_scalar(cursor, &codepoint);
        if (length == 0) {
            fprintf(stream, "\\x%02X", (unsigned int)*cursor++);
        } else if (zupt_codepoint_is_display_control(codepoint)) {
            for (size_t i = 0; i < length; i++)
                fprintf(stream, "\\x%02X", (unsigned int)cursor[i]);
            cursor += length;
        } else {
            fwrite(cursor, 1, length, stream);
            cursor += length;
        }
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
 * ZUPT-LZHP is a better default since its simpler decoder doesn't
 * benefit from SIMD as much.
 *
 * Detection order:
 *   1. Compile-time: __x86_64__ + __AVX2__ → VaptVupt (compiled with -mavx2)
 *   2. Runtime: zupt_cpu.has_avx2 → VaptVupt (for x86_64 without -mavx2)
 *   3. Compile-time: __aarch64__ + __ARM_NEON → VaptVupt (NEON decode)
 *   4. Fallback: ZUPT-LZHP (works everywhere)
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
    /* The block IS the codec's LZ window: matches never cross a block
     * boundary, so a small block throttles the "large-window extreme"
     * parser (512 KiB gave text 3.75x where a whole-file window gives
     * 7.6x — measured on codec 2.65.0). Higher levels therefore get a
     * larger block. Trade-offs held in mind: (a) block size also sets
     * --dedup granularity, so the speed-first low levels (where dedup is
     * most used) stay small; and (b) extreme's optimal DP is ~O(block),
     * so the extreme block is bounded at 8 MiB — 16 MiB bought only a few
     * more percent of ratio for ~2.5x the encode time, not worth it as a
     * default (raise it explicitly with -b for archival runs). Decode
     * speed and memory are unaffected by block size. */
    if (level <= 2) return   131072;   /* fast: speed + MT + dedup granularity */
    if (level <= 4) return  1u << 20;  /* 1 MiB */
    if (level <= 6) return  2u << 20;  /* 2 MiB */
    if (level <= 7) return  4u << 20;  /* 4 MiB balanced: ~free, big ratio win */
    return                  8u << 20;  /* 8 MiB extreme: large usable window */
}

/* Block size when --dedup is active. Dedup detects duplicate BLOCKS, so a
 * large block almost never finds a duplicate (an 8 MiB block rarely repeats
 * byte-exactly), collapsing the dedup ratio to 1.0x — directly opposed to the
 * large-window compression goal, which they share the one block_size knob for.
 * With --dedup the user has chosen block-level dup detection, so pick a small
 * block that actually finds repeats (256 KiB is the classic dedup granularity;
 * finer than that costs index memory for little gain on real backups). */
static uint32_t auto_block_size_dedup(int level) {
    return level <= 2 ? 131072u : 262144u;
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
    if (!b || !v) return -1;
    *v = 0;
    unsigned int shift = 0;
    for (size_t n = 0; n < blen && n < 10; n++) {
        uint8_t byte = b[n];
        uint8_t payload = (uint8_t)(byte & 0x7fu);
        /* A uint64_t varint has only one payload bit in byte ten.  Check it
         * before shifting so malformed values cannot wrap modulo 2^64. */
        if (n == 9 && (byte & 0xfeu) != 0) return -1;
        *v |= (uint64_t)payload << shift;
        if ((byte & 0x80u) == 0) {
            /* Writers always use the shortest representation.  Reject an
             * overlong final zero so a scalar has exactly one wire encoding. */
            if (n > 0 && payload == 0) return -1;
            return (int)n + 1;
        }
        shift += 7;
    }
    return -1;
}
int zupt_write_varint(FILE *f, uint64_t v) {
    uint8_t b[10]; int n=zupt_encode_varint(b,v); return fwrite(b,1,(size_t)n,f)==(size_t)n?n:-1;
}
int zupt_read_varint(FILE *f, uint64_t *v) {
    if (!f || !v) return -1;
    *v = 0;
    unsigned int shift = 0;
    for (int i = 0; i < 10; i++) {
        int raw = fgetc(f);
        if (raw == EOF) return -1;
        uint8_t byte = (uint8_t)raw;
        uint8_t payload = (uint8_t)(byte & 0x7fu);
        if (i == 9 && (byte & 0xfeu) != 0) return -1;
        *v |= (uint64_t)payload << shift;
        if ((byte & 0x80u) == 0) {
            if (i > 0 && payload == 0) return -1;
            return i + 1;
        }
        shift += 7;
    }
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════
 * DIRECTORY TRAVERSAL
 * ═══════════════════════════════════════════════════════════════════ */

void zupt_filelist_init(zupt_filelist_t *fl) {
    fl->paths = NULL; fl->arc_paths = NULL;
    fl->count = 0; fl->capacity = 0;
}
void zupt_filelist_free(zupt_filelist_t *fl) {
    for (int i = 0; i < fl->count; i++) { free(fl->paths[i]); free(fl->arc_paths[i]); }
    free(fl->paths); free(fl->arc_paths);
    fl->paths = fl->arc_paths = NULL;
    fl->count = fl->capacity = 0;
}

static char *zupt_normalize_archive_path(const char *path, int fold_ascii) {
    if (!path) return NULL;
    size_t length = strlen(path);
    char *normalized = (char *)malloc(length + 1);
    if (!normalized) return NULL;
    size_t out = 0;
    int previous_separator = 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c == '/' || c == '\\') {
            if (previous_separator) continue;
            normalized[out++] = '/';
            previous_separator = 1;
            continue;
        }
        previous_separator = 0;
        if (fold_ascii && c >= 'A' && c <= 'Z')
            c = (unsigned char)(c + ('a' - 'A'));
        normalized[out++] = (char)c;
    }
    normalized[out] = '\0';
    return normalized;
}

void zupt_filelist_add(zupt_filelist_t *fl, const char *disk, const char *arc) {
    if (!fl || !disk || !arc || fl->count < 0 || fl->capacity < 0 ||
        fl->capacity > ZUPT_MAX_FILES ||
        fl->count > fl->capacity || fl->count >= ZUPT_MAX_FILES) {
        zupt_internal_filelist_mark_failed(fl);
        return;
    }
    if (fl->count >= fl->capacity) {
        int new_cap = fl->capacity ? fl->capacity * 2 : 256;
        if (new_cap < fl->capacity || new_cap > ZUPT_MAX_FILES)
            new_cap = ZUPT_MAX_FILES;
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
            zupt_internal_filelist_mark_failed(fl);
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
    char *new_path = strdup(disk);
    char *new_arc = zupt_normalize_archive_path(arc, 0);
    if (!new_path || !new_arc) {
        free(new_path);
        free(new_arc);
        fprintf(stderr, "  Warning: out of memory adding '%s'\n", disk);
        zupt_internal_filelist_mark_failed(fl);
        return;
    }
    fl->paths[fl->count] = new_path;
    fl->arc_paths[fl->count] = new_arc;
    fl->count++;
}

static int is_dir(const char *path) {
#ifdef _WIN32
    DWORD attr = zupt_win_get_attributes_utf8(path);
    return attr != INVALID_FILE_ATTRIBUTES &&
           (attr & FILE_ATTRIBUTE_DIRECTORY) &&
           !(attr & FILE_ATTRIBUTE_REPARSE_POINT);
#else
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

#ifdef _WIN32
static int zupt_win_has_extended_or_device_prefix(const char *path) {
    return path &&
           (path[0] == '\\' || path[0] == '/') &&
           (path[1] == '\\' || path[1] == '/') &&
           (path[2] == '?' || path[2] == '.') &&
           (path[3] == '\\' || path[3] == '/');
}
#endif

static int zupt_path_is_safe(const char *path);
static int zupt_path_has_unsafe_text(const char *path);

void zupt_collect_files(zupt_filelist_t *fl, const char *path, const char *base) {
#ifdef _WIN32
    /* Extended/device namespaces need separate canonicalisation rules.  Until
     * that support exists, reject them before creating an archive; otherwise
     * a name such as \\?\C:\\file would be stored with a colon and the archive
     * would correctly refuse to extract its own unsafe entry. */
    if (zupt_win_has_extended_or_device_prefix(path) ||
        zupt_win_has_extended_or_device_prefix(base)) {
        fprintf(stderr,
                "  Error: Windows extended/device namespace inputs are unsupported: %s\n",
                path ? path : "(null)");
        zupt_internal_filelist_mark_failed(fl);
        return;
    }
#endif
    if (!is_dir(path)) {
        /* Skip non-regular files (symlinks, devices, FIFOs, sockets) */
        if (!zupt_is_regular_file(path)) {
            fprintf(stderr, "  Error: input is unreadable or not a regular file: %s\n", path);
            zupt_internal_filelist_mark_failed(fl);
            return;
        }
        const char *arc = base;
#ifdef _WIN32
        /* A drive designator is a disk namespace prefix, never archive data. */
        if (((arc[0] >= 'A' && arc[0] <= 'Z') ||
             (arc[0] >= 'a' && arc[0] <= 'z')) && arc[1] == ':')
            arc += 2;
#endif
        while (arc[0]=='.' && (arc[1]=='/'||arc[1]=='\\')) arc+=2;
        while (*arc=='/'||*arc=='\\') arc++;
        if (*arc == '\0') arc = path;
        while (*arc=='/'||*arc=='\\') arc++;
#ifndef _WIN32
        if (strchr(arc, '\\') != NULL) {
            fprintf(stderr,
                    "  Error: POSIX input name contains a non-portable backslash.\n");
            zupt_internal_filelist_mark_failed(fl);
            return;
        }
#endif
        if (!zupt_path_is_safe(arc)) {
            fprintf(stderr,
                    "  Error: input would create an unsafe archive path.\n");
            zupt_internal_filelist_mark_failed(fl);
            return;
        }
        zupt_filelist_add(fl, path, arc);
        return;
    }

#ifdef _WIN32
    wchar_t *wide_path = zupt_win_utf8_to_wide_alloc(path);
    if (!wide_path) { zupt_internal_filelist_mark_failed(fl); return; }
    size_t path_length = wcslen(wide_path);
    if (path_length > ZUPT_MAX_PATH - 3) {
        free(wide_path); zupt_internal_filelist_mark_failed(fl); return;
    }
    wchar_t pattern[ZUPT_MAX_PATH];
    memcpy(pattern, wide_path, (path_length + 1) * sizeof(wchar_t));
    free(wide_path);
    if (path_length > 0 && pattern[path_length - 1] != L'/' &&
        pattern[path_length - 1] != L'\\')
        pattern[path_length++] = L'\\';
    pattern[path_length++] = L'*';
    pattern[path_length] = L'\0';

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        zupt_internal_filelist_mark_failed(fl);
        return;
    }
    do {
        if (fd.cFileName[0]==L'.' && (fd.cFileName[1]==L'\0' ||
            (fd.cFileName[1]==L'.' && fd.cFileName[2]==L'\0'))) continue;
        char *name = zupt_win_wide_to_utf8_alloc(fd.cFileName);
        if (!name) { zupt_internal_filelist_mark_failed(fl); break; }
        char child_disk[ZUPT_MAX_PATH], child_arc[ZUPT_MAX_PATH];
        int disk_length = snprintf(child_disk, sizeof(child_disk),
                                   "%s\\%s", path, name);
        int arc_length = snprintf(child_arc, sizeof(child_arc),
                                  "%s/%s", base, name);
        free(name);
        if (disk_length < 0 || (size_t)disk_length >= sizeof(child_disk) ||
            arc_length < 0 || (size_t)arc_length >= sizeof(child_arc)) {
            zupt_internal_filelist_mark_failed(fl);
            break;
        }
        zupt_collect_files(fl, child_disk, child_arc);
        if (zupt_internal_filelist_failed(fl)) break;
    } while (FindNextFileW(h, &fd));
    if (!zupt_internal_filelist_failed(fl) &&
        GetLastError() != ERROR_NO_MORE_FILES)
        zupt_internal_filelist_mark_failed(fl);
    FindClose(h);
#else
    DIR *d = opendir(path);
    if (!d) { zupt_internal_filelist_mark_failed(fl); return; }
    struct dirent *ent;
    for (;;) {
        errno = 0;
        ent = readdir(d);
        if (!ent) {
            if (errno != 0) zupt_internal_filelist_mark_failed(fl);
            break;
        }
        if (ent->d_name[0]=='.' && (ent->d_name[1]=='\0' ||
            (ent->d_name[1]=='.' && ent->d_name[2]=='\0'))) continue;
        char child_disk[ZUPT_MAX_PATH], child_arc[ZUPT_MAX_PATH];
        int disk_length = snprintf(child_disk, sizeof(child_disk),
                                   "%s/%s", path, ent->d_name);
        int arc_length = snprintf(child_arc, sizeof(child_arc),
                                  "%s/%s", base, ent->d_name);
        if (disk_length < 0 || (size_t)disk_length >= sizeof(child_disk) ||
            arc_length < 0 || (size_t)arc_length >= sizeof(child_arc)) {
            zupt_internal_filelist_mark_failed(fl);
            break;
        }
        zupt_collect_files(fl, child_disk, child_arc);
        if (zupt_internal_filelist_failed(fl)) break;
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

void zupt_serialize_archive_header(const zupt_archive_header_t *header,
                                   uint8_t out[ZUPT_ARCHIVE_HEADER_SIZE]) {
    memset(out, 0, ZUPT_ARCHIVE_HEADER_SIZE);
    memcpy(out, header->magic, sizeof(header->magic));
    out[6] = header->version_major;
    out[7] = header->version_minor;
    zupt_le32_put(out + 8, header->global_flags);
    zupt_le64_put(out + 12, header->creation_time);
    memcpy(out + 20, header->archive_id, sizeof(header->archive_id));
    zupt_le64_put(out + 36, header->encryption_header_off);
    zupt_le64_put(out + 44, header->comment_offset);
    memcpy(out + 52, header->reserved, sizeof(header->reserved));
}

void zupt_serialize_footer(const zupt_footer_t *footer,
                           uint8_t out[ZUPT_FOOTER_SIZE]) {
    memset(out, 0, ZUPT_FOOTER_SIZE);
    zupt_le64_put(out, footer->index_offset);
    zupt_le64_put(out + 8, footer->total_blocks);
    zupt_le64_put(out + 16, footer->archive_checksum);
    memcpy(out + 24, footer->footer_magic, sizeof(footer->footer_magic));
    zupt_le32_put(out + 28, footer->footer_version);
}

static void deserialize_archive_header(
    const uint8_t in[ZUPT_ARCHIVE_HEADER_SIZE], zupt_archive_header_t *header) {
    memset(header, 0, sizeof(*header));
    memcpy(header->magic, in, sizeof(header->magic));
    header->version_major = in[6];
    header->version_minor = in[7];
    header->global_flags = zupt_le32_get(in + 8);
    header->creation_time = zupt_le64_get(in + 12);
    memcpy(header->archive_id, in + 20, sizeof(header->archive_id));
    header->encryption_header_off = zupt_le64_get(in + 36);
    header->comment_offset = zupt_le64_get(in + 44);
    memcpy(header->reserved, in + 52, sizeof(header->reserved));
}

static void deserialize_footer(const uint8_t in[ZUPT_FOOTER_SIZE],
                               zupt_footer_t *footer) {
    memset(footer, 0, sizeof(*footer));
    footer->index_offset = zupt_le64_get(in);
    footer->total_blocks = zupt_le64_get(in + 8);
    footer->archive_checksum = zupt_le64_get(in + 16);
    memcpy(footer->footer_magic, in + 24, sizeof(footer->footer_magic));
    footer->footer_version = zupt_le32_get(in + 28);
}

int zupt_write_archive_header(FILE *stream,
                              const zupt_archive_header_t *header) {
    uint8_t serialized[ZUPT_ARCHIVE_HEADER_SIZE];
    zupt_serialize_archive_header(header, serialized);
    return fwrite(serialized, 1, sizeof(serialized), stream) ==
           sizeof(serialized) ? 0 : -1;
}

int zupt_write_footer(FILE *stream, const zupt_footer_t *footer) {
    uint8_t serialized[ZUPT_FOOTER_SIZE];
    zupt_serialize_footer(footer, serialized);
    return fwrite(serialized, 1, sizeof(serialized), stream) ==
           sizeof(serialized) ? 0 : -1;
}

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
        if (zupt_write_archive_header(out, hdr) != 0) return ZUPT_ERR_IO;
        fseeko(out, 0, SEEK_END);

        if (!opts->quiet)
            fprintf(stderr, "  Encryption: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC)\n\n");
    } else if (opts->sdk_mode && opts->pq_mode) {
        /* ─── SDK V2 PQ MODE (libvuptsdk: HKDF combiner + commitment + HPKE) ─── */
        hdr->global_flags |= ZUPT_FLAG_PQ_HYBRID;

        uint8_t enc_hdr_buf[1500];
        size_t enc_hdr_len = 0;
        if (!opts->quiet)
            fprintf(stderr, "  PQ key encapsulation via libvuptsdk (HKDF-SHA3 + commitment + HPKE)...\n");
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
        if (zupt_write_archive_header(out, hdr) != 0) return ZUPT_ERR_IO;
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
        if (zupt_write_archive_header(out, hdr) != 0) return ZUPT_ERR_IO;
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
        if (zupt_write_archive_header(out, hdr) != 0) return ZUPT_ERR_IO;
        fseeko(out, 0, SEEK_END);

        if (!opts->quiet)
            fprintf(stderr, "  Encryption: PQ Hybrid (ML-KEM-768 + X25519) + AES-256-CTR + HMAC-SHA256\n\n");
    } else {
        /* ─── PASSWORD MODE ───
         *
         * v2.4.1+: default to Argon2id (libvuptsdk path, enc_type=0x04).
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
        if (opts->kdf_legacy_pbkdf2) {
#else
        /* No libvuptsdk in this build: Argon2id is unavailable, so the password
         * KDF is always native PBKDF2-SHA256 (600k iters, AES-256-CTR + HMAC-
         * SHA256). Archives written this way are readable by any build. */
        {
#endif
            uint8_t salt[ZUPT_SALT_SIZE], nonce[ZUPT_NONCE_SIZE];
            zupt_random_bytes(salt, ZUPT_SALT_SIZE);
            zupt_random_bytes(nonce, ZUPT_NONCE_SIZE);

            if (!opts->quiet)
                fprintf(stderr, "  Deriving encryption key (PBKDF2-SHA256, %d iterations)...\n",
                        ZUPT_KDF_ITERATIONS);
            zupt_derive_keys(&opts->keyring, opts->password, salt, nonce, ZUPT_KDF_ITERATIONS);

            uint8_t enc_hdr[53];
            enc_hdr[0] = ZUPT_ENC_PBKDF2;
            memcpy(enc_hdr + 1, salt, 32);
            memcpy(enc_hdr + 33, nonce, 16);
            zupt_le32_put(enc_hdr + 49, ZUPT_KDF_ITERATIONS);

            zupt_w8(out, ZUPT_BLOCK_MAGIC_0); zupt_w8(out, ZUPT_BLOCK_MAGIC_1);
            zupt_w8(out, ZUPT_BLOCK_ENC_HEADER);
            zupt_w16le(out, ZUPT_CODEC_STORE); zupt_w16le(out, 0);
            zupt_write_varint(out, 53); zupt_write_varint(out, 53);
            zupt_w64le(out, zupt_xxh64(enc_hdr, 53, 0));
            if (fwrite(enc_hdr, 1, 53, out) != 53) return ZUPT_ERR_IO;
#ifdef ZUPT_WITH_SDK
        } else {
            /* Argon2id default (v2.4.1+) */
            uint8_t enc_hdr[ZUPT_ARGON2_HDR_LEN_V2];
            size_t enc_hdr_len = 0;
            if (!opts->quiet)
                fprintf(stderr, "  Deriving encryption key (Argon2id, libvuptsdk)...\n");
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
#else
        }
#endif

        fseeko(out, 0, SEEK_SET);
        if (zupt_write_archive_header(out, hdr) != 0) return ZUPT_ERR_IO;
        fseeko(out, 0, SEEK_END);

        if (!opts->quiet)
            fprintf(stderr, "  Encryption: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC)\n\n");
    }

    return ZUPT_OK;
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
 *   3. Reject empty, ".", and ".." components (splitting on / and \).
 *   4. Reject Windows ADS syntax, control characters, trailing dots/spaces,
 *      and reserved DOS device names on every platform.  This keeps an
 *      archive made on POSIX safe when it is later extracted on Windows.
 *   5. Embedded NUL bytes are rejected while parsing the length-delimited
 *      index entry, before it reaches this C-string interface.
 *
 * Returns 1 if path is safe, 0 if it should be rejected.
 */
static int zupt_ascii_equal_ci(const char *value, size_t value_len,
                               const char *literal) {
    size_t literal_len = strlen(literal);
    if (value_len != literal_len) return 0;
    for (size_t i = 0; i < value_len; i++) {
        unsigned char a = (unsigned char)value[i];
        unsigned char b = (unsigned char)literal[i];
        if (a >= 'a' && a <= 'z') a = (unsigned char)(a - ('a' - 'A'));
        if (b >= 'a' && b <= 'z') b = (unsigned char)(b - ('a' - 'A'));
        if (a != b) return 0;
    }
    return 1;
}

static int zupt_is_reserved_dos_name(const char *component, size_t len) {
    size_t base_len = 0;
    while (base_len < len && component[base_len] != '.') base_len++;
    if (zupt_ascii_equal_ci(component, base_len, "CON") ||
        zupt_ascii_equal_ci(component, base_len, "PRN") ||
        zupt_ascii_equal_ci(component, base_len, "AUX") ||
        zupt_ascii_equal_ci(component, base_len, "NUL"))
        return 1;
    if (base_len == 4 &&
        ((component[0] == 'C' || component[0] == 'c') &&
         (component[1] == 'O' || component[1] == 'o') &&
         (component[2] == 'M' || component[2] == 'm') &&
         component[3] >= '1' && component[3] <= '9'))
        return 1;
    if (base_len == 4 &&
        ((component[0] == 'L' || component[0] == 'l') &&
         (component[1] == 'P' || component[1] == 'p') &&
         (component[2] == 'T' || component[2] == 't') &&
         component[3] >= '1' && component[3] <= '9'))
        return 1;
    return 0;
}

static int zupt_path_is_safe(const char *path) {
    if (!path || !*path) return 0;
    size_t len = strlen(path);
    if (len >= ZUPT_MAX_PATH) return 0;
    if (zupt_path_has_unsafe_text(path)) return 0;

    /* Absolute paths */
    if (path[0] == '/' || path[0] == '\\') return 0;
    /* A colon is a drive designator or NTFS alternate-data-stream marker. */
    if (memchr(path, ':', len) != NULL) return 0;

    /* Component scan: split on '/' and '\\' */
    const char *start = path;
    for (size_t i = 0; i <= len; i++) {
        if (path[i] == '/' || path[i] == '\\' || path[i] == '\0') {
            size_t complen = (size_t)(path + i - start);
            /* Repeated separators are normalized by the descriptor walk;
             * a trailing separator cannot name a regular-file entry. */
            if (complen == 0) {
                if (i == len) return 0;
                start = path + i + 1;
                continue;
            }
            if ((complen == 1 && start[0] == '.') ||
                (complen == 2 && start[0] == '.' && start[1] == '.'))
                return 0;
            if (start[complen - 1] == '.' || start[complen - 1] == ' ' ||
                zupt_is_reserved_dos_name(start, complen))
                return 0;
            for (size_t j = 0; j < complen; j++) {
                unsigned char c = (unsigned char)start[j];
                if (c < 0x20 || c == 0x7f) return 0;
            }
            start = path + i + 1;
        }
    }

    return 1;
}

static int zupt_path_has_unsafe_text(const char *path) {
    if (!path) return 1;
    const unsigned char *cursor = (const unsigned char *)path;
    while (*cursor != '\0') {
        uint32_t codepoint = 0;
        size_t length = zupt_decode_utf8_scalar(cursor, &codepoint);
        if (length == 0 || zupt_codepoint_is_display_control(codepoint))
            return 1;
        cursor += length;
    }
    return 0;
}

struct zupt_atomic_output {
    FILE *stream;
#if defined(_WIN32)
    HANDLE parent_handle;
    HANDLE temp_handle;
    WCHAR final_name[ZUPT_MAX_PATH];
#else
    int parent_fd;
    char final_name[ZUPT_MAX_PATH];
    char temp_name[96];
#endif
};

typedef struct zupt_atomic_output zupt_output_file_t;

static void zupt_output_init(zupt_output_file_t *output) {
    memset(output, 0, sizeof(*output));
#if defined(_WIN32)
    output->parent_handle = INVALID_HANDLE_VALUE;
    output->temp_handle = INVALID_HANDLE_VALUE;
#else
    output->parent_fd = -1;
#endif
}

#if defined(_WIN32)
static void zupt_win_set_nt_errno(NTSTATUS status) {
    if (status == (NTSTATUS)0xC0000034L || /* STATUS_OBJECT_NAME_NOT_FOUND */
        status == (NTSTATUS)0xC000003AL) { /* STATUS_OBJECT_PATH_NOT_FOUND */
        errno = ENOENT;
    } else if (status == (NTSTATUS)0xC0000035L) { /* NAME_COLLISION */
        errno = EEXIST;
    } else {
        errno = EACCES;
    }
}

static int zupt_win_is_plain_directory(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info;
    return GetFileInformationByHandle(handle, &info) &&
           (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

static int zupt_win_component_to_wide(const char *component, UINT code_page,
                                      WCHAR wide[ZUPT_MAX_PATH]) {
    DWORD flags = code_page == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0;
    int length = MultiByteToWideChar(code_page, flags, component, -1,
                                     wide, ZUPT_MAX_PATH);
    return length > 1 && length <= ZUPT_MAX_PATH;
}

/* New archives use UTF-8. Fall back to ACP only for legacy Windows archives
 * written before archive names were normalized at collection time. */
static int zupt_win_archive_component_to_wide(
    const char *component, WCHAR wide[ZUPT_MAX_PATH]) {
    return zupt_win_component_to_wide(component, CP_UTF8, wide) ||
           zupt_win_component_to_wide(component, CP_ACP, wide);
}

/* Open one component relative to an already resolved directory handle.  This
 * deliberately avoids a second string-path resolution between checking a
 * directory and using it, which would permit a junction/reparse-point race. */
static HANDLE zupt_win_open_relative_dir_wide(HANDLE parent, const WCHAR *wide,
                                              int create) {
    UNICODE_STRING name;
    name.Buffer = (PWSTR)wide;
    name.Length = (USHORT)(wcslen(wide) * sizeof(WCHAR));
    name.MaximumLength = name.Length + sizeof(WCHAR);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE,
                               parent, NULL);
    IO_STATUS_BLOCK status_block;
    HANDLE handle = INVALID_HANDLE_VALUE;
    NTSTATUS status = NtCreateFile(
        &handle,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes, &status_block, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        create ? FILE_OPEN_IF : FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT |
            FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (status < 0 || handle == INVALID_HANDLE_VALUE) {
        zupt_win_set_nt_errno(status);
        return INVALID_HANDLE_VALUE;
    }
    if (!zupt_win_is_plain_directory(handle)) {
        CloseHandle(handle);
        errno = EACCES;
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

static HANDLE zupt_win_open_drive_root(const WCHAR *full) {
    WCHAR root[4] = {full[0], L':', L'\\', L'\0'};
    HANDLE handle = CreateFileW(
        root, FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle != INVALID_HANDLE_VALUE && !zupt_win_is_plain_directory(handle)) {
        CloseHandle(handle);
        handle = INVALID_HANDLE_VALUE;
    }
    if (handle == INVALID_HANDLE_VALUE) errno = EACCES;
    return handle;
}

static HANDLE zupt_win_create_temp(HANDLE parent, const WCHAR *name) {
    UNICODE_STRING object_name;
    object_name.Buffer = (PWSTR)name;
    object_name.Length = (USHORT)(wcslen(name) * sizeof(WCHAR));
    object_name.MaximumLength = object_name.Length + sizeof(WCHAR);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &object_name, OBJ_CASE_INSENSITIVE,
                               parent, NULL);
    IO_STATUS_BLOCK status_block;
    HANDLE handle = INVALID_HANDLE_VALUE;
    NTSTATUS status = NtCreateFile(
        &handle, FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
            DELETE | SYNCHRONIZE,
        &attributes, &status_block, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT |
            FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (status < 0) {
        zupt_win_set_nt_errno(status);
        SetLastError(errno == EEXIST ? ERROR_FILE_EXISTS : ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

static int zupt_win_delete_by_handle(HANDLE handle) {
    FILE_DISPOSITION_INFO disposition;
    disposition.DeleteFile = TRUE;
    int deleted = SetFileInformationByHandle(handle, FileDispositionInfo,
                                             &disposition,
                                             sizeof(disposition)) != 0;
    if (!deleted) errno = EACCES;
    return deleted;
}

static int zupt_win_publish_by_handle(HANDLE handle, HANDLE parent,
                                      const WCHAR *final_name, int replace) {
    size_t name_bytes = wcslen(final_name) * sizeof(WCHAR);
    if (name_bytes == 0 ||
        name_bytes > MAXDWORD - sizeof(FILE_RENAME_INFORMATION))
        return 0;
    size_t info_size = sizeof(FILE_RENAME_INFORMATION) + name_bytes;
    FILE_RENAME_INFORMATION *info =
        (FILE_RENAME_INFORMATION *)calloc(1, info_size);
    if (!info) return 0;
    info->ReplaceIfExists = replace ? TRUE : FALSE;
    info->RootDirectory = parent;
    info->FileNameLength = (ULONG)name_bytes;
    memcpy(info->FileName, final_name, name_bytes);
    IO_STATUS_BLOCK status_block;
    NTSTATUS status = NtSetInformationFile(
        handle, &status_block, info, (ULONG)info_size, FileRenameInformation);
    free(info);
    if (status < 0) zupt_win_set_nt_errno(status);
    return status >= 0;
}

/* Resolve an UTF-8 directory path one component at a time while holding a
 * handle to each parent.  Reparse-point ancestors are rejected.  UNC and
 * extended-length paths remain intentionally unsupported until they can be
 * given the same handle-relative guarantees. */
static HANDLE zupt_win_open_output_root_utf8(const char *root_path, int create) {
    WCHAR *wide_root = zupt_win_utf8_to_wide_alloc(
        (root_path && *root_path) ? root_path : ".");
    WCHAR full[ZUPT_MAX_PATH + 256];
    if (!wide_root ||
        !_wfullpath(full, wide_root, sizeof(full) / sizeof(full[0]))) {
        free(wide_root);
        errno = EINVAL;
        return INVALID_HANDLE_VALUE;
    }
    free(wide_root);

    if (full[0] == L'\\' && full[1] == L'\\') {
        errno = EINVAL;
        return INVALID_HANDLE_VALUE;
    }
    for (WCHAR *p = full; *p; p++) if (*p == L'/') *p = L'\\';
    if (!(full[0] && full[1] == L':' && full[2] == L'\\')) {
        errno = EINVAL;
        return INVALID_HANDLE_VALUE;
    }

    HANDLE current = zupt_win_open_drive_root(full);
    if (current == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    WCHAR *scan = full + 3;
    while (*scan) {
        WCHAR *separator = wcschr(scan, L'\\');
        if (separator) *separator = L'\0';
        HANDLE next = zupt_win_open_relative_dir_wide(current, scan, create);
        if (next == INVALID_HANDLE_VALUE) {
            if (separator) *separator = L'\\';
            CloseHandle(current);
            return INVALID_HANDLE_VALUE;
        }
        CloseHandle(current);
        current = next;
        if (!separator) break;
        *separator = L'\\';
        scan = separator + 1;
    }
    return current;
}

#else
/* Resolve symlinks in the user-selected portion of an output root once, then
 * use only the resulting physical path.  This keeps normal macOS paths such
 * as /tmp -> private/tmp usable without following a symlink after traversal
 * has begun.  A suffix that does not exist yet is accepted only when it has
 * no unresolved ".." component. */
static int zupt_canonical_output_root(const char *path, int create,
                                      char resolved[ZUPT_MAX_PATH]) {
    const char *root = (path && *path) ? path : ".";
    size_t root_len = strlen(root);
    if (root_len >= ZUPT_MAX_PATH) { errno = ENAMETOOLONG; return 0; }

    if (realpath(root, resolved)) return 1;
    if (!create || errno != ENOENT) return 0;

    char probe[ZUPT_MAX_PATH];
    char suffix[ZUPT_MAX_PATH] = {0};
    memcpy(probe, root, root_len + 1);

    for (;;) {
        size_t probe_len = strlen(probe);
        while (probe_len > 1 && probe[probe_len - 1] == '/')
            probe[--probe_len] = '\0';

        if (realpath(probe, resolved)) break;
        if (errno != ENOENT) return 0;

        char *separator = strrchr(probe, '/');
        char *leaf = separator ? separator + 1 : probe;
        if (*leaf == '\0') { errno = EINVAL; return 0; }
        if (strcmp(leaf, "..") == 0) { errno = EINVAL; return 0; }

        if (strcmp(leaf, ".") != 0) {
            size_t leaf_len = strlen(leaf);
            size_t suffix_len = strlen(suffix);
            size_t separator_len = suffix_len ? 1u : 0u;
            if (leaf_len + separator_len + suffix_len >= sizeof(suffix)) {
                errno = ENAMETOOLONG;
                return 0;
            }
            memmove(suffix + leaf_len + separator_len, suffix,
                    suffix_len + 1);
            memcpy(suffix, leaf, leaf_len);
            if (separator_len) suffix[leaf_len] = '/';
        }

        if (!separator) {
            memcpy(probe, ".", 2);
        } else if (separator == probe) {
            probe[1] = '\0';
        } else {
            *separator = '\0';
        }
    }

    if (*suffix) {
        size_t resolved_len = strlen(resolved);
        size_t suffix_len = strlen(suffix);
        int needs_separator = resolved_len > 0 && resolved[resolved_len - 1] != '/';
        if (resolved_len + (size_t)needs_separator + suffix_len >= ZUPT_MAX_PATH) {
            errno = ENAMETOOLONG;
            return 0;
        }
        if (needs_separator) resolved[resolved_len++] = '/';
        memcpy(resolved + resolved_len, suffix, suffix_len + 1);
    }
    return 1;
}

/* Open every component of the canonical output root relative to a pinned
 * descriptor.  Symlinks created or exchanged after canonicalization are
 * rejected, and a trailing slash is treated like the same path without it. */
static int zupt_open_output_root(const char *path, int create) {
    char resolved[ZUPT_MAX_PATH];
    if (!zupt_canonical_output_root(path, create, resolved)) return -1;
    const char *root = resolved;
    size_t root_len = strlen(root);
    if (root_len >= ZUPT_MAX_PATH) { errno = ENAMETOOLONG; return -1; }

    int current_fd = open(root[0] == '/' ? "/" : ".",
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current_fd < 0) return -1;

    char copy[ZUPT_MAX_PATH];
    memcpy(copy, root, root_len + 1);
    char *component = copy;
    if (*component == '/') while (*component == '/') component++;

    while (*component != '\0') {
        char *separator = strchr(component, '/');
        if (separator) *separator = '\0';
        if (*component != '\0' && strcmp(component, ".") != 0) {
            /* The extraction root is chosen by the user, so a lexical ".."
             * here is legitimate (for example, -o ../restore).  It is still
             * resolved relative to the pinned descriptor.  Only archive entry
             * components are forbidden from containing "..". */
            if (create && strcmp(component, "..") != 0 &&
                mkdirat(current_fd, component, 0755) != 0 && errno != EEXIST) {
                close(current_fd); return -1;
            }
            int next_fd = openat(current_fd, component,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (next_fd < 0) { close(current_fd); return -1; }
            close(current_fd);
            current_fd = next_fd;
        }
        if (!separator) break;
        component = separator + 1;
        while (*component == '/') component++;
    }
    return current_fd;
}
#endif

typedef struct {
    uint64_t device;
    uint64_t file;
    uint64_t size;
    uint64_t mtime_marker;
    uint64_t archive_mtime;
} zupt_input_identity_t;

static int zupt_input_identity_equal(const zupt_input_identity_t *left,
                                     const zupt_input_identity_t *right) {
    return left && right && left->device == right->device &&
           left->file == right->file && left->size == right->size &&
           left->mtime_marker == right->mtime_marker;
}

static int zupt_input_identity_from_stream(FILE *stream,
                                           zupt_input_identity_t *identity) {
    if (!stream || !identity) { errno = EINVAL; return 0; }
#ifdef _WIN32
    intptr_t os_handle = _get_osfhandle(_fileno(stream));
    if (os_handle == -1) { errno = EBADF; return 0; }
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER size;
    HANDLE handle = (HANDLE)os_handle;
    if (!GetFileInformationByHandle(handle, &info) ||
        !GetFileSizeEx(handle, &size) || size.QuadPart < 0 ||
        GetFileType(handle) != FILE_TYPE_DISK ||
        (info.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        errno = EACCES;
        return 0;
    }
    identity->device = (uint64_t)info.dwVolumeSerialNumber;
    identity->file = ((uint64_t)info.nFileIndexHigh << 32) |
                     (uint64_t)info.nFileIndexLow;
    identity->size = (uint64_t)size.QuadPart;
    uint64_t filetime_ticks =
        ((uint64_t)info.ftLastWriteTime.dwHighDateTime << 32) |
        (uint64_t)info.ftLastWriteTime.dwLowDateTime;
    const uint64_t windows_unix_epoch = 116444736000000000ULL;
    if (filetime_ticks < windows_unix_epoch ||
        filetime_ticks - windows_unix_epoch > UINT64_MAX / 100ULL) {
        errno = EOVERFLOW;
        return 0;
    }
    identity->mtime_marker = filetime_ticks;
    identity->archive_mtime =
        (filetime_ticks - windows_unix_epoch) * 100ULL;
#else
    struct stat info;
    if (fstat(fileno(stream), &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size < 0) {
        if (errno == 0) errno = EINVAL;
        return 0;
    }
    identity->device = (uint64_t)info.st_dev;
    identity->file = (uint64_t)info.st_ino;
    identity->size = (uint64_t)info.st_size;
#if defined(__APPLE__)
    identity->mtime_marker =
        (uint64_t)info.st_mtimespec.tv_sec * 1000000000ULL +
        (uint64_t)info.st_mtimespec.tv_nsec;
#else
    identity->mtime_marker =
        (uint64_t)info.st_mtim.tv_sec * 1000000000ULL +
        (uint64_t)info.st_mtim.tv_nsec;
#endif
    identity->archive_mtime = identity->mtime_marker;
#endif
    return 1;
}

/* Resolve and pin the parent, then open the leaf without following a
 * symlink/reparse point. Validation is performed on the descriptor actually
 * consumed by compression, closing the collection-to-read race. */
static FILE *zupt_open_regular_input(const char *path,
                                     zupt_input_identity_t *identity) {
    if (!path || !*path || !identity || strlen(path) >= ZUPT_MAX_PATH) {
        errno = EINVAL;
        return NULL;
    }
    char split[ZUPT_MAX_PATH];
    memcpy(split, path, strlen(path) + 1);
#ifdef _WIN32
    if ((split[0] == '/' || split[0] == '\\') ||
        (split[0] != '\0' && split[1] == ':' &&
         split[2] != '/' && split[2] != '\\')) {
        errno = EINVAL;
        return NULL;
    }
    char *slash = strrchr(split, '/');
    char *backslash = strrchr(split, '\\');
    char *separator = slash;
    if (backslash && (!separator || backslash > separator))
        separator = backslash;
#else
    char *separator = strrchr(split, '/');
#endif
    const char *leaf = split;
    const char *parent = ".";
#ifdef _WIN32
    char drive_root[4] = {0};
#endif
    if (separator) {
        leaf = separator + 1;
#ifdef _WIN32
        if (separator == split + 2 && split[1] == ':') {
            drive_root[0] = split[0];
            drive_root[1] = ':';
            drive_root[2] = '\\';
            parent = drive_root;
        } else {
#endif
            *separator = '\0';
            if (split[0] != '\0') parent = split;
#ifndef _WIN32
            else parent = "/";
#endif
#ifdef _WIN32
        }
#endif
    }
    if (*leaf == '\0' || strcmp(leaf, ".") == 0 ||
        strcmp(leaf, "..") == 0) {
        errno = EINVAL;
        return NULL;
    }

#ifdef _WIN32
    HANDLE parent_handle = zupt_win_open_output_root_utf8(parent, 0);
    if (parent_handle == INVALID_HANDLE_VALUE) return NULL;
    WCHAR *wide_leaf = zupt_win_utf8_to_wide_alloc(leaf);
    if (!wide_leaf) {
        CloseHandle(parent_handle);
        errno = EINVAL;
        return NULL;
    }
    UNICODE_STRING name;
    name.Buffer = wide_leaf;
    name.Length = (USHORT)(wcslen(wide_leaf) * sizeof(WCHAR));
    name.MaximumLength = name.Length + sizeof(WCHAR);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE,
                               parent_handle, NULL);
    IO_STATUS_BLOCK status_block;
    HANDLE handle = INVALID_HANDLE_VALUE;
    NTSTATUS status = NtCreateFile(
        &handle, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes, &status_block, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT |
            FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    free(wide_leaf);
    CloseHandle(parent_handle);
    if (status < 0 || handle == INVALID_HANDLE_VALUE) {
        zupt_win_set_nt_errno(status);
        return NULL;
    }
    int descriptor = _open_osfhandle((intptr_t)handle,
                                     _O_RDONLY | _O_BINARY);
    if (descriptor < 0) {
        CloseHandle(handle);
        return NULL;
    }
    FILE *stream = _fdopen(descriptor, "rb");
    if (!stream) {
        _close(descriptor);
        return NULL;
    }
#else
    int parent_fd = zupt_open_output_root(parent, 0);
    if (parent_fd < 0) return NULL;
    int descriptor = openat(parent_fd, leaf,
                            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int open_errno = errno;
    close(parent_fd);
    errno = open_errno;
    if (descriptor < 0) return NULL;
    int descriptor_flags = fcntl(descriptor, F_GETFL);
    if (descriptor_flags < 0 ||
        fcntl(descriptor, F_SETFL, descriptor_flags & ~O_NONBLOCK) != 0) {
        int saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
        return NULL;
    }
    FILE *stream = fdopen(descriptor, "rb");
    if (!stream) {
        int saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
        return NULL;
    }
#endif
    if (!zupt_input_identity_from_stream(stream, identity)) {
        int saved_errno = errno;
        fclose(stream);
        errno = saved_errno;
        return NULL;
    }
    return stream;
}

/* SECURITY: create a private temporary output relative to a pinned extraction
 * root.  Every parent is opened without following symlinks.  The final name
 * is published only after validation and a successful close, and an existing
 * regular file, symlink, or hardlink is never overwritten.
 *
 * Defends against the case where an attacker has placed a symlink in the
 * output directory before extraction, e.g. ~/Downloads/innocent.txt → /etc/passwd.
 * On Linux/BSD/macOS, every directory is opened with openat(), O_DIRECTORY
 * and O_NOFOLLOW. The leaf uses O_NOFOLLOW + O_EXCL, so extraction never
 * truncates a pre-existing symlink, hardlink, or regular file. Refusing an
 * existing leaf also closes the hardlink variant of the same attack.
 *
 * Windows rejects reparse-point parents and uses CREATE_NEW with
 * FILE_FLAG_OPEN_REPARSE_POINT for the leaf.
 */
static int zupt_safe_fopen_output(const char *dir, const char *entry,
                                  char *display, size_t display_size,
                                  zupt_output_file_t *output) {
    zupt_output_init(output);
    if (!entry || !*entry || !display || display_size == 0) {
        errno = EINVAL;
        return 0;
    }
    int written;
    if (dir) written = snprintf(display, display_size, "%s%c%s", dir, ZUPT_PATH_SEP, entry);
    else written = snprintf(display, display_size, "%s", entry);
    if (written < 0 || (size_t)written >= display_size) {
        errno = ENAMETOOLONG;
        return 0;
    }

#if defined(_WIN32)
    HANDLE current = zupt_win_open_output_root_utf8(dir, 1);
    if (current == INVALID_HANDLE_VALUE) return 0;

    char relative[ZUPT_MAX_PATH];
    size_t entry_len = strlen(entry);
    if (entry_len == 0 || entry_len >= sizeof(relative)) {
        CloseHandle(current);
        errno = ENAMETOOLONG;
        return 0;
    }
    memcpy(relative, entry, entry_len + 1);
    for (char *p = relative; *p; p++) if (*p == '\\') *p = '/';

    char *component = relative;
    for (char *p = relative; ; p++) {
        if (*p != '/' && *p != '\0') continue;
        char saved = *p;
        *p = '\0';
        if (*component == '\0') {
            if (saved == '\0') { CloseHandle(current); errno = EINVAL; return 0; }
        } else if (saved == '\0') {
            if (!zupt_win_archive_component_to_wide(component,
                                                    output->final_name)) {
                CloseHandle(current);
                errno = EINVAL;
                return 0;
            }
            break;
        } else {
            WCHAR archive_component[ZUPT_MAX_PATH];
            if (!zupt_win_archive_component_to_wide(component,
                                                    archive_component)) {
                CloseHandle(current);
                errno = EINVAL;
                return 0;
            }
            HANDLE next = zupt_win_open_relative_dir_wide(
                current, archive_component, 1);
            if (next == INVALID_HANDLE_VALUE) {
                CloseHandle(current);
                return 0;
            }
            CloseHandle(current);
            current = next;
        }
        component = p + 1;
    }

    uint8_t nonce[12];
    zupt_random_bytes(nonce, sizeof(nonce));
    WCHAR nonce_hex[25];
    for (size_t i = 0; i < sizeof(nonce); i++)
        swprintf(nonce_hex + i * 2, 3, L"%02x", nonce[i]);
    WCHAR temp_name[48];
    if (swprintf(temp_name, sizeof(temp_name) / sizeof(temp_name[0]),
                 L".zupt-tmp-%ls", nonce_hex) < 0) {
        CloseHandle(current);
        return 0;
    }

    HANDLE handle = zupt_win_create_temp(current, temp_name);
    if (handle == INVALID_HANDLE_VALUE) { CloseHandle(current); return 0; }
    if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(),
                         &output->temp_handle, 0, FALSE,
                         DUPLICATE_SAME_ACCESS)) {
        zupt_win_delete_by_handle(handle);
        CloseHandle(handle);
        CloseHandle(current);
        return 0;
    }
    output->parent_handle = current;
    int fd = _open_osfhandle((intptr_t)handle, _O_WRONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(handle);
        zupt_win_delete_by_handle(output->temp_handle);
        CloseHandle(output->temp_handle);
        CloseHandle(output->parent_handle);
        zupt_output_init(output);
        return 0;
    }
    output->stream = _fdopen(fd, "wb");
    if (!output->stream) {
        _close(fd);
        zupt_win_delete_by_handle(output->temp_handle);
        CloseHandle(output->temp_handle);
        CloseHandle(output->parent_handle);
        zupt_output_init(output);
        return 0;
    }
    return 1;
#else
    char relative[ZUPT_MAX_PATH];
    size_t entry_len = strlen(entry);
    if (entry_len == 0 || entry_len >= sizeof(relative)) {
        errno = ENAMETOOLONG;
        return 0;
    }
    memcpy(relative, entry, entry_len + 1);
    for (char *p = relative; *p; p++) if (*p == '\\') *p = '/';

    int parent_fd = zupt_open_output_root(dir, 1);
    if (parent_fd < 0) return 0;

    char *component = relative;
    for (char *p = relative; ; p++) {
        if (*p != '/' && *p != '\\' && *p != '\0') continue;
        char saved = *p;
        *p = '\0';
        if (*component == '\0' || strcmp(component, ".") == 0) {
            if (saved == '\0') { close(parent_fd); errno = EINVAL; return 0; }
        } else if (saved == '\0') {
            if (strlen(component) >= sizeof(output->final_name)) {
                close(parent_fd); errno = ENAMETOOLONG; return 0;
            }
            memcpy(output->final_name, component, strlen(component) + 1);

            uint8_t nonce[12];
            zupt_random_bytes(nonce, sizeof(nonce));
            char nonce_hex[25];
            for (size_t i = 0; i < sizeof(nonce); i++)
                snprintf(nonce_hex + i * 2, 3, "%02x", nonce[i]);
            snprintf(output->temp_name, sizeof(output->temp_name),
                     ".zupt-tmp-%s", nonce_hex);
            int fd = openat(parent_fd, output->temp_name,
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                            0600);
            if (fd < 0) { close(parent_fd); return 0; }
            output->stream = fdopen(fd, "wb");
            if (!output->stream) {
                close(fd); unlinkat(parent_fd, output->temp_name, 0);
                close(parent_fd); return 0;
            }
            output->parent_fd = parent_fd;
            return 1;
        } else {
            if (mkdirat(parent_fd, component, 0755) != 0 && errno != EEXIST) {
                close(parent_fd);
                return 0;
            }
            int next_fd = openat(parent_fd, component,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (next_fd < 0) { close(parent_fd); return 0; }
            close(parent_fd);
            parent_fd = next_fd;
        }
        if (saved == '\0') break;
        component = p + 1;
    }
    close(parent_fd);
    errno = EINVAL;
    return 0;
#endif
}

/* Open a private, seekable stream in the destination archive's directory.
 * The POSIX parent is canonicalized once and then pinned component-by-component;
 * Windows rejects reparse-point parents.  The
 * caller may overwrite an existing archive at publication time, but only by
 * replacing that directory entry: a symlink or hardlink target is never
 * opened or truncated. */
static int zupt_safe_fopen_archive(const char *path,
                                   zupt_output_file_t *output) {
    zupt_output_init(output);
    if (!path || !*path) { errno = EINVAL; return 0; }

    size_t path_len = strlen(path);
    if (path_len >= ZUPT_MAX_PATH) { errno = ENAMETOOLONG; return 0; }

    const char *separator = strrchr(path, '/');
#if defined(_WIN32)
    const char *backslash = strrchr(path, '\\');
    if (!separator || (backslash && backslash > separator)) separator = backslash;
#endif
    const char *leaf = separator ? separator + 1 : path;
    size_t leaf_len = strlen(leaf);
    if (leaf_len == 0 || leaf_len >= ZUPT_MAX_PATH ||
        (leaf_len == 1 && leaf[0] == '.') ||
        (leaf_len == 2 && leaf[0] == '.' && leaf[1] == '.')) {
        errno = EINVAL;
        return 0;
    }

    char parent[ZUPT_MAX_PATH];
    if (!separator) {
        memcpy(parent, ".", 2);
    } else {
        size_t parent_len = (size_t)(separator - path);
        if (parent_len == 0) {
            parent[0] = *separator;
            parent[1] = '\0';
#if defined(_WIN32)
        } else if (parent_len == 2 && path[1] == ':') {
            memcpy(parent, path, 3);
            parent[3] = '\0';
#endif
        } else {
            if (parent_len >= sizeof(parent)) { errno = ENAMETOOLONG; return 0; }
            memcpy(parent, path, parent_len);
            parent[parent_len] = '\0';
        }
    }

#if defined(_WIN32)
    if (!zupt_path_is_safe(leaf) ||
        !zupt_win_component_to_wide(leaf, CP_UTF8, output->final_name)) {
        errno = EINVAL;
        return 0;
    }
    HANDLE current = zupt_win_open_output_root_utf8(parent, 0);
    if (current == INVALID_HANDLE_VALUE) return 0;

    HANDLE handle = INVALID_HANDLE_VALUE;
    for (unsigned int attempt = 0; attempt < 16; attempt++) {
        uint8_t nonce[12];
        zupt_random_bytes(nonce, sizeof(nonce));
        WCHAR nonce_hex[25];
        for (size_t i = 0; i < sizeof(nonce); i++)
            swprintf(nonce_hex + i * 2, 3, L"%02x", nonce[i]);
        WCHAR temp_name[64];
        if (swprintf(temp_name,
                     sizeof(temp_name) / sizeof(temp_name[0]),
                     L".zupt-archive-%ls", nonce_hex) < 0) {
            CloseHandle(current);
            return 0;
        }
        handle = zupt_win_create_temp(current, temp_name);
        if (handle != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_FILE_EXISTS &&
            GetLastError() != ERROR_ALREADY_EXISTS)
            break;
    }
    if (handle == INVALID_HANDLE_VALUE) { CloseHandle(current); return 0; }
    if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(),
                         &output->temp_handle, 0, FALSE,
                         DUPLICATE_SAME_ACCESS)) {
        zupt_win_delete_by_handle(handle);
        CloseHandle(handle);
        CloseHandle(current);
        return 0;
    }
    output->parent_handle = current;
    int fd = _open_osfhandle((intptr_t)handle, _O_RDWR | _O_BINARY);
    if (fd < 0) {
        CloseHandle(handle);
        zupt_win_delete_by_handle(output->temp_handle);
        CloseHandle(output->temp_handle);
        CloseHandle(output->parent_handle);
        zupt_output_init(output);
        return 0;
    }
    output->stream = _fdopen(fd, "w+b");
    if (!output->stream) {
        _close(fd);
        zupt_win_delete_by_handle(output->temp_handle);
        CloseHandle(output->temp_handle);
        CloseHandle(output->parent_handle);
        zupt_output_init(output);
        return 0;
    }
    return 1;
#else
    if (leaf_len >= sizeof(output->final_name)) {
        errno = ENAMETOOLONG;
        return 0;
    }
    memcpy(output->final_name, leaf, leaf_len + 1);
    int parent_fd = zupt_open_output_root(parent, 0);
    if (parent_fd < 0) return 0;

    int fd = -1;
    for (unsigned int attempt = 0; attempt < 16; attempt++) {
        uint8_t nonce[12];
        zupt_random_bytes(nonce, sizeof(nonce));
        char nonce_hex[25];
        for (size_t i = 0; i < sizeof(nonce); i++)
            snprintf(nonce_hex + i * 2, 3, "%02x", nonce[i]);
        int n = snprintf(output->temp_name, sizeof(output->temp_name),
                         ".zupt-archive-%s", nonce_hex);
        if (n < 0 || (size_t)n >= sizeof(output->temp_name)) {
            close(parent_fd);
            errno = ENAMETOOLONG;
            return 0;
        }
        fd = openat(parent_fd, output->temp_name,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    if (fd < 0) { close(parent_fd); return 0; }
    output->stream = fdopen(fd, "w+b");
    if (!output->stream) {
        close(fd);
        unlinkat(parent_fd, output->temp_name, 0);
        close(parent_fd);
        return 0;
    }
    output->parent_fd = parent_fd;
    return 1;
#endif
}

/* Close and either atomically publish or remove the private temporary file.
 * Returns zero only when the requested outcome completed successfully. */
static int zupt_finish_output(zupt_output_file_t *output, int publish,
                              int replace) {
    int failed = 0;
    if (!output || !output->stream) return -1;
    if (ferror(output->stream)) failed = 1;
    if (fflush(output->stream) != 0) failed = 1;
#if !defined(_WIN32)
    if (publish && !failed && fsync(fileno(output->stream)) != 0) failed = 1;
#endif
    if (fclose(output->stream) != 0) failed = 1;
    output->stream = NULL;
    if (failed) publish = 0;

#if defined(_WIN32)
    if (publish && !failed && !FlushFileBuffers(output->temp_handle))
        failed = 1;
    if (publish && !failed &&
        !zupt_win_publish_by_handle(output->temp_handle,
                                    output->parent_handle,
                                    output->final_name, replace))
        failed = 1;
    if (!publish || failed) {
        if (!zupt_win_delete_by_handle(output->temp_handle)) failed = 1;
    }
    if (!CloseHandle(output->temp_handle)) failed = 1;
    if (!CloseHandle(output->parent_handle)) failed = 1;
    output->temp_handle = INVALID_HANDLE_VALUE;
    output->parent_handle = INVALID_HANDLE_VALUE;
#else
    int namespace_changed = 0;
    if (publish) {
        int publish_result = replace
            ? renameat(output->parent_fd, output->temp_name,
                       output->parent_fd, output->final_name)
            : linkat(output->parent_fd, output->temp_name,
                     output->parent_fd, output->final_name, 0);
        if (publish_result != 0) failed = 1;
        else namespace_changed = 1;
    }
    if (unlinkat(output->parent_fd, output->temp_name, 0) == 0) {
        namespace_changed = 1;
    } else if (errno != ENOENT) {
        failed = 1;
    }
    /* Directory fsync is unsupported on some otherwise valid filesystems.
     * Attempt it for crash durability without weakening runtime atomicity. */
    if (namespace_changed) (void)fsync(output->parent_fd);
    close(output->parent_fd);
    output->parent_fd = -1;
#endif
    return failed ? -1 : 0;
}

zupt_atomic_output_t *zupt_atomic_output_open(const char *output_path,
                                               FILE **stream_out) {
    if (!stream_out) { errno = EINVAL; return NULL; }
    *stream_out = NULL;
    zupt_atomic_output_t *output =
        (zupt_atomic_output_t *)calloc(1, sizeof(*output));
    if (!output) return NULL;
    if (!zupt_safe_fopen_archive(output_path, output)) {
        free(output);
        return NULL;
    }
    *stream_out = output->stream;
    return output;
}

int zupt_atomic_output_finish(zupt_atomic_output_t *output, int publish) {
    if (!output) { errno = EINVAL; return -1; }
    int result = zupt_finish_output(output, publish, 1);
    free(output);
    return result;
}

static int zupt_write_verified_chunk(FILE *stream, const uint8_t *data,
                                     size_t length, uint64_t expected_size,
                                     uint64_t *written, uint64_t *hash) {
    if (!stream || !written || !hash || (length > 0 && !data) ||
        *written > expected_size || (uint64_t)length > expected_size - *written)
        return 0;
    if (length > 0) {
        if (fwrite(data, 1, length, stream) != length) return 0;
        *hash = zupt_xxh64(data, length, *hash);
    }
    *written += (uint64_t)length;
    return 1;
}

/* Safe ftello wrapper: returns 0 on error (caller should check context) */
/* F-09 of v2.3.1: serialize the canonical per-block frame preface for use as
 * extended-AAD input to the per-block MAC. Format is fixed-width little-endian
 * rather than the variable-width on-disk representation, so the authenticated
 * input is independent of parser storage and stays stable across platforms.
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

/* Compare existing paths by kernel identity, following the final symlink.
 * Return 1 when equal, 0 when the output does not exist or differs, and -1 on
 * an inspection error.  An alias of an input must never be replaced at final
 * archive publication, even when --force was requested by the CLI. */
static int zupt_compress_paths_same_file(const char *output_path,
                                         const char *input_path) {
#ifdef _WIN32
    wchar_t *wide_output = zupt_win_utf8_to_wide_alloc(output_path);
    wchar_t *wide_input = zupt_win_utf8_to_wide_alloc(input_path);
    if (!wide_output || !wide_input) {
        free(wide_output);
        free(wide_input);
        errno = EINVAL;
        return -1;
    }
    HANDLE output = CreateFileW(
        wide_output, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wide_output);
    if (output == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        free(wide_input);
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            return 0;
        errno = EACCES;
        return -1;
    }
    HANDLE input = CreateFileW(
        wide_input, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wide_input);
    if (input == INVALID_HANDLE_VALUE) {
        CloseHandle(output);
        errno = EACCES;
        return -1;
    }
    BY_HANDLE_FILE_INFORMATION output_info;
    BY_HANDLE_FILE_INFORMATION input_info;
    int inspected = GetFileInformationByHandle(output, &output_info) != 0 &&
                    GetFileInformationByHandle(input, &input_info) != 0;
    if (!CloseHandle(input)) inspected = 0;
    if (!CloseHandle(output)) inspected = 0;
    if (!inspected) {
        errno = EIO;
        return -1;
    }
    return output_info.dwVolumeSerialNumber == input_info.dwVolumeSerialNumber &&
           output_info.nFileIndexHigh == input_info.nFileIndexHigh &&
           output_info.nFileIndexLow == input_info.nFileIndexLow;
#else
    struct stat output_info;
    struct stat input_info;
    if (stat(output_path, &output_info) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) return 0;
        return -1;
    }
    if (stat(input_path, &input_info) != 0) return -1;
    return output_info.st_dev == input_info.st_dev &&
           output_info.st_ino == input_info.st_ino;
#endif
}

static int zupt_compare_path_keys(const void *left, const void *right) {
    const char *const *a = (const char *const *)left;
    const char *const *b = (const char *const *)right;
    return strcmp(*a, *b);
}

#ifdef _WIN32
static int zupt_compare_windows_path_keys(const void *left,
                                          const void *right) {
    const WCHAR *const *a = (const WCHAR *const *)left;
    const WCHAR *const *b = (const WCHAR *const *)right;
    int relation = CompareStringOrdinal(*a, -1, *b, -1, TRUE);
    if (relation == CSTR_LESS_THAN) return -1;
    if (relation == CSTR_GREATER_THAN) return 1;
    if (relation == CSTR_EQUAL) return 0;
    return wcscmp(*a, *b);
}
#endif

/* Every archive entry must map to one portable extraction destination.
 * Separators are canonicalized and ASCII case is folded for collision
 * detection because Windows extraction is case-insensitive. */
static zupt_error_t zupt_validate_archive_destinations(
        const char **archive_paths, int count, int require_safe_paths) {
    if (count < 0 || (count > 0 && !archive_paths))
        return ZUPT_ERR_INVALID;
    if (count < 2) {
        if (count == 1 && require_safe_paths &&
            !zupt_path_is_safe(archive_paths[0])) {
            fprintf(stderr, "Error: unsafe archive path.\n");
            return ZUPT_ERR_INVALID;
        }
        return ZUPT_OK;
    }
    char **keys = (char **)calloc((size_t)count, sizeof(*keys));
    if (!keys) return ZUPT_ERR_NOMEM;
    zupt_error_t result = ZUPT_OK;
    for (int i = 0; i < count; i++) {
        if (require_safe_paths && !zupt_path_is_safe(archive_paths[i])) {
            fprintf(stderr, "Error: unsafe archive path.\n");
            result = ZUPT_ERR_INVALID;
            break;
        }
        keys[i] = zupt_normalize_archive_path(archive_paths[i], 1);
        if (!keys[i]) {
            result = ZUPT_ERR_NOMEM;
            break;
        }
    }
    if (result == ZUPT_OK) {
        qsort(keys, (size_t)count, sizeof(*keys), zupt_compare_path_keys);
        for (int i = 1; i < count; i++) {
            size_t previous_length = strlen(keys[i - 1]);
            if (strcmp(keys[i - 1], keys[i]) == 0 ||
                (strncmp(keys[i - 1], keys[i], previous_length) == 0 &&
                 keys[i][previous_length] == '/')) {
                fprintf(stderr,
                        "Error: archive paths collide after portable normalization: %s\n",
                        keys[i]);
                result = ZUPT_ERR_INVALID;
                break;
            }
        }
    }
#ifdef _WIN32
    /* CompareStringOrdinal models the case-insensitive Unicode namespace used
     * by normal Windows extraction roots; ASCII folding alone misses pairs
     * such as non-ASCII upper/lower-case spellings. */
    WCHAR **windows_keys = NULL;
    if (result == ZUPT_OK) {
        windows_keys = (WCHAR **)calloc((size_t)count, sizeof(*windows_keys));
        if (!windows_keys) result = ZUPT_ERR_NOMEM;
    }
    if (result == ZUPT_OK) {
        for (int i = 0; i < count; i++) {
            windows_keys[i] = zupt_win_utf8_to_wide_alloc(keys[i]);
            if (!windows_keys[i]) {
                fprintf(stderr, "Error: archive path is not valid UTF-8.\n");
                result = ZUPT_ERR_INVALID;
                break;
            }
        }
    }
    if (result == ZUPT_OK) {
        qsort(windows_keys, (size_t)count, sizeof(*windows_keys),
              zupt_compare_windows_path_keys);
        for (int i = 1; i < count; i++) {
            size_t previous_length = wcslen(windows_keys[i - 1]);
            size_t current_length = wcslen(windows_keys[i]);
            int equal = CompareStringOrdinal(windows_keys[i - 1], -1,
                                             windows_keys[i], -1,
                                             TRUE) == CSTR_EQUAL;
            int prefix = current_length > previous_length &&
                windows_keys[i][previous_length] == L'/' &&
                CompareStringOrdinal(windows_keys[i - 1],
                                     (int)previous_length,
                                     windows_keys[i],
                                     (int)previous_length,
                                     TRUE) == CSTR_EQUAL;
            if (equal || prefix) {
                fprintf(stderr,
                        "Error: archive paths collide in the Windows namespace.\n");
                result = ZUPT_ERR_INVALID;
                break;
            }
        }
    }
    if (windows_keys) {
        for (int i = 0; i < count; i++) free(windows_keys[i]);
        free(windows_keys);
    }
#endif
    for (int i = 0; i < count; i++) free(keys[i]);
    free(keys);
    return result;
}

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
    if (num_files < 0 ||
        (uint64_t)num_files >
            (uint64_t)(ZUPT_MAX_INDEX_ALLOC_BYTES /
                       sizeof(zupt_index_entry_t))) {
        fprintf(stderr, "Error: file count exceeds the safe index-memory limit.\n");
        return ZUPT_ERR_OVERFLOW;
    }
    zupt_error_t path_error =
        zupt_validate_archive_destinations(arc_paths, num_files, 1);
    if (path_error != ZUPT_OK) return path_error;
    for (int file_index = 0; file_index < num_files; file_index++) {
        int same_file = zupt_compress_paths_same_file(
            output_path, disk_paths[file_index]);
        if (same_file > 0) {
            fprintf(stderr,
                    "Error: archive output and input '%s' are the same file.\n",
                    disk_paths[file_index]);
            return ZUPT_ERR_INVALID;
        }
        if (same_file < 0) {
            fprintf(stderr,
                    "Error: cannot inspect archive output/input identity safely: %s\n",
                    strerror(errno));
            return ZUPT_ERR_IO;
        }
    }
    if (opts->block_size == 0) opts->block_size = opts->dedup ? auto_block_size_dedup(opts->level) : auto_block_size(opts->level);

    /* Resolve AUTO codec before compression */
    if (opts->codec_id == ZUPT_CODEC_AUTO)
        opts->codec_id = zupt_resolve_auto_codec();

    FILE *out = NULL;
    zupt_atomic_output_t *atomic_output =
        zupt_atomic_output_open(output_path, &out);
    if (!atomic_output) {
        fprintf(stderr, "Error: Cannot create '%s': %s\n",
                output_path, strerror(errno));
        return ZUPT_ERR_IO;
    }

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
    if (opts->dedup) hdr.global_flags |= ZUPT_FLAG_DEDUP;
    if (opts->dedup && opts->encrypt)
        hdr.global_flags |= ZUPT_FLAG_AUTH_DEDUP_REFS;
    hdr.creation_time = now_ns();
    gen_uuid(hdr.archive_id);
    if (zupt_write_archive_header(out, &hdr) != 0) write_err = 1;

    if (opts->encrypt) {
        zupt_error_t enc_err = write_enc_header(out, &hdr, opts);
        if (enc_err != ZUPT_OK) {
            zupt_atomic_output_finish(atomic_output, 0);
            return enc_err;
        }
    }

    zupt_index_entry_t *index = (zupt_index_entry_t*)calloc((size_t)num_files, sizeof(zupt_index_entry_t));
    uint8_t *rbuf = (uint8_t*)malloc(opts->block_size);
    uint8_t *cbuf = (uint8_t*)malloc(zupt_lzh_bound(opts->block_size) + 512);
    if (!index || !rbuf || !cbuf) {
        free(index); free(rbuf); free(cbuf);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }

    uint64_t total_blocks = 0, total_in = 0, total_out = 0;
    /* block_seq is now PER-FILE: resets at the start of each file's compress.
     * This decouples the seq used for AAD-binding from cross-file ordering,
     * letting extract compute the same seq via simple per-file counting from 0.
     */
    time_t start_time = time(NULL);

    /* Dedup context (NULL if --dedup not set) */
    zupt_dedup_ctx_t *dedup = opts->dedup ? zupt_dedup_init() : NULL;
    if (opts->dedup && !dedup) {
        free(index); free(rbuf); free(cbuf);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }

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
    /* Record multithreading only after worker creation succeeds. Dedup and a
     * worker-start failure both use the single-threaded encoder, so marking
     * either archive as multithreaded would make its metadata inaccurate. */
    if (effective_threads > 1) {
        int64_t output_position = ftello(out);
        hdr.global_flags |= ZUPT_FLAG_MULTITHREADED;
        if (output_position < 0 || fseeko(out, 0, SEEK_SET) != 0 ||
            zupt_write_archive_header(out, &hdr) != 0 ||
            fseeko(out, output_position, SEEK_SET) != 0) {
            zpar_destroy(pctx);
            zupt_dedup_free(dedup);
            free(index); free(rbuf); free(cbuf);
            zupt_atomic_output_finish(atomic_output, 0);
            return ZUPT_ERR_IO;
        }
    }

    for (int fi = 0; fi < num_files; fi++) {
        /* Per-file block_seq counter (resets to 0 for each file) — used as
         * AAD in encrypt/decrypt. Extract recomputes the same counter from
         * the same per-file zero baseline, ensuring MAC consistency. */
        uint64_t block_seq = 0;
        zupt_input_identity_t input_identity;
        FILE *inf = zupt_open_regular_input(disk_paths[fi], &input_identity);
        if (!inf) {
            fprintf(stderr, "Error: Cannot read input '%s': %s\n",
                    disk_paths[fi], strerror(errno));
            write_err = 1;
            break;
        }

        if (input_identity.size > INT64_MAX) {
            fprintf(stderr, "Error: Cannot determine input size '%s'\n",
                    disk_paths[fi]);
            fclose(inf);
            write_err = 1;
            break;
        }
        int64_t file_size = (int64_t)input_identity.size;

        strncpy(index[fi].path, arc_paths[fi], ZUPT_MAX_PATH-1);
        index[fi].uncompressed_size = (uint64_t)file_size;
        index[fi].first_block_offset = safe_ftello(out);
        index[fi].modification_time = input_identity.archive_mtime;
        index[fi].attributes = 0644;
        index[fi].block_count = 0;

        char sz_buf[32]; zupt_format_size((uint64_t)file_size, sz_buf, sizeof(sz_buf));
        if (zupt_internal_verbose(opts))
            fprintf(stderr, "  %s (%s)\n", arc_paths[fi], sz_buf);

        /* Chained hash: xxh64 over concatenated file content */
        uint64_t file_hash_state = 0;
        uint64_t file_comp = 0;
        uint64_t remaining = (uint64_t)file_size;
        uint64_t file_done = 0;

        if (pctx && effective_threads > 1) {
            /* ─── MULTI-THREADED COMPRESSION PATH ─── */
            /* Batch: read up to N blocks, submit to workers, collect in order */
            int *pending_slots = (int *)malloc((size_t)effective_threads * sizeof(int));
            uint64_t *pending_seqs = (uint64_t *)malloc((size_t)effective_threads * sizeof(uint64_t));
            if (!pending_slots || !pending_seqs) {
                free(pending_slots); free(pending_seqs); fclose(inf);
                write_err = 1;
                break;
            }

            while (remaining > 0) {
                int npending = 0;

                /* Fill batch: read and submit up to N blocks */
                while (remaining > 0 && npending < effective_threads) {
                    size_t chunk = remaining < opts->block_size
                        ? (size_t)remaining : opts->block_size;
                    size_t nread = fread(rbuf, 1, chunk, inf);
                    if (nread != chunk) {
                        fprintf(stderr, "  Read failed or input changed: %s\n", disk_paths[fi]);
                        write_err = 1;
                        break;
                    }

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

                if (!zupt_internal_verbose(opts) && !opts->quiet && file_size > (int64_t)opts->block_size)
                    show_progress(arc_paths[fi], file_done, (uint64_t)file_size);
            }

            free(pending_slots);
            free(pending_seqs);
        } else {
            /* ─── SINGLE-THREADED COMPRESSION PATH (bit-for-bit v0.5.1) ─── */
            while (remaining > 0) {
            size_t chunk = remaining < opts->block_size
                ? (size_t)remaining : opts->block_size;
            size_t nread = fread(rbuf, 1, chunk, inf);
            if (nread != chunk) {
                fprintf(stderr, "  Read failed or input changed: %s\n", disk_paths[fi]);
                write_err = 1;
                break;
            }

            uint64_t checksum = zupt_xxh64(rbuf, nread, 0);
            uint8_t dedup_digest[32];
            if (dedup) zupt_sha256(rbuf, nread, dedup_digest);
            uint64_t logical_aad_seq =
                (((uint64_t)(fi + 1)) << 32) | block_seq;
            /* Chained hash: feed previous hash as seed for next block */
            file_hash_state = zupt_xxh64(rbuf, nread, file_hash_state);

            /* ─── Dedup check: skip compression if block already written ─── */
            if (dedup) {
                zupt_dedup_record_block(dedup);
                uint64_t ref_off = 0, referenced_aad_seq = 0;
                uint32_t ref_sz = 0;
                if (zupt_dedup_lookup_secure(dedup, checksum, dedup_digest,
                                             &ref_off, &ref_sz,
                                             &referenced_aad_seq) &&
                    ref_sz == (uint32_t)nread) {
                    /* Fingerprint match + same size — write reference block */
                    const zupt_keyring_t *ref_keyring = opts->encrypt
                        ? &opts->keyring : NULL;
                    if (zupt_dedup_write_ref_secure(
                            out, ref_off, (uint32_t)nread, checksum,
                            logical_aad_seq, referenced_aad_seq,
                            ref_keyring) != 0) {
                        write_err = 1;
                        break;
                    }
                    zupt_dedup_record_hit(dedup, nread);
                    file_comp += opts->encrypt ? 64u : 8u;
                    index[fi].block_count++;
                    total_blocks++;
                    block_seq++;
                    remaining -= nread;
                    file_done += nread;
                    if (!zupt_internal_verbose(opts) && !opts->quiet && file_size > (int64_t)opts->block_size)
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
                /* Bind every new DATA frame to its file and logical block.
                 * An authenticated DEDUP_REF carries this source sequence so
                 * a later reference can verify the original frame without
                 * weakening all dedup DATA frames to sequence zero. */
                uint64_t aad_seq = logical_aad_seq;
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
                if (!enc_payload) {
                    fclose(inf);
                    if (pctx) zpar_destroy(pctx);
                    zupt_dedup_free(dedup);
                    free(index); free(rbuf); free(cbuf);
                    zupt_atomic_output_finish(atomic_output, 0);
                    return ZUPT_ERR_NOMEM;
                }
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
                zupt_dedup_insert_secure(dedup, checksum, dedup_digest,
                                         this_block_off, (uint32_t)nread,
                                         logical_aad_seq);

            free(enc_payload);
            file_comp += payload_size;
            index[fi].block_count++;
            total_blocks++;
            block_seq++;
            remaining -= nread;
            file_done += nread;

            if (!zupt_internal_verbose(opts) && !opts->quiet && file_size > (int64_t)opts->block_size)
                show_progress(arc_paths[fi], file_done, (uint64_t)file_size);
        } /* end while (remaining > 0) */
        } /* end else (single-threaded) */

        if (write_err) {
            fclose(inf);
            break;
        }

        zupt_input_identity_t final_identity;
        if (!zupt_input_identity_from_stream(inf, &final_identity) ||
            !zupt_input_identity_equal(&input_identity, &final_identity)) {
            fprintf(stderr, "Error: Input changed while reading '%s'\n",
                    disk_paths[fi]);
            fclose(inf);
            write_err = 1;
            break;
        }

        index[fi].compressed_size = file_comp;
        index[fi].content_hash = file_hash_state;
        total_in += index[fi].uncompressed_size;
        total_out += index[fi].compressed_size;
        fclose(inf);

        if (zupt_internal_verbose(opts)) {
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
        zupt_dedup_free(dedup);
        free(index); free(rbuf); free(cbuf);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_IO;
    }

    /* ─── F-12 of v2.4.3: optional comment block ─── */
    {
        zupt_error_t cerr = write_comment_block(out, &hdr, opts, &total_blocks);
        if (cerr != ZUPT_OK) {
            fprintf(stderr, "Error: Failed to write comment block\n");
            zupt_dedup_free(dedup);
            free(index); free(rbuf); free(cbuf);
            zupt_atomic_output_finish(atomic_output, 0);
            return cerr;
        }
        if (opts->has_comment && hdr.comment_offset != 0) {
            /* Rewrite the archive header so on-disk hdr.comment_offset
             * matches the in-memory hdr that the AIT will sign at the
             * end of the function. */
            int64_t save = ftello(out);
            fseeko(out, 0, SEEK_SET);
            if (zupt_write_archive_header(out, &hdr) != 0) {
                fprintf(stderr, "Error: Failed to update header with comment offset\n");
                zupt_dedup_free(dedup);
                free(index); free(rbuf); free(cbuf);
                zupt_atomic_output_finish(atomic_output, 0);
                return ZUPT_ERR_IO;
            }
            fseeko(out, save, SEEK_SET);
        }
    }

    /* ─── Central Index ─── */
    uint64_t index_offset = safe_ftello(out);
    if (num_files < 0 ||
        (size_t)num_files > SIZE_MAX / (ZUPT_MAX_PATH + 128)) {
        zupt_dedup_free(dedup);
        free(index); free(rbuf); free(cbuf);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_OVERFLOW;
    }
    size_t icap = (size_t)num_files * (ZUPT_MAX_PATH + 128);
    uint8_t *ibuf = (uint8_t*)malloc(icap);
    if (!ibuf) {
        zupt_dedup_free(dedup);
        free(index); free(rbuf); free(cbuf);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }

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
    if (!ic) {
        zupt_dedup_free(dedup);
        free(ibuf); free(index); free(rbuf); free(cbuf);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }
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
        if (!enc_idx) {
            zupt_dedup_free(dedup);
            free(ic); free(ibuf); free(index); free(rbuf); free(cbuf);
            zupt_atomic_output_finish(atomic_output, 0);
            return ZUPT_ERR_NOMEM;
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
    if (zupt_write_footer(out, &ft) != 0) write_err = 1;

    /* F-08 of v2.3.0: archive-integrity-trailer follows the footer.
     * Encrypted: HMAC over hdr || ft[0..23]. Plaintext: XXH64 best-effort. */
    if (!write_err) {
        const zupt_keyring_t *kr = opts->encrypt ? &opts->keyring : NULL;
        if (zupt_format_ait_write(out, &hdr, &ft, kr) != 0) write_err = 1;
    }

    if (zupt_atomic_output_finish(atomic_output, !write_err) != 0)
        write_err = 1;

    if (write_err) {
        fprintf(stderr, "Error: Compression failed; no partial archive was published.\n");
        zupt_dedup_free(dedup);
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
    if (num_files < 0 ||
        (uint64_t)num_files >
            (uint64_t)(ZUPT_MAX_INDEX_ALLOC_BYTES /
                       sizeof(zupt_index_entry_t))) {
        fprintf(stderr, "Error: file count exceeds the safe index-memory limit.\n");
        return ZUPT_ERR_OVERFLOW;
    }
    zupt_error_t path_error =
        zupt_validate_archive_destinations(arc_paths, num_files, 1);
    if (path_error != ZUPT_OK) return path_error;
    for (int file_index = 0; file_index < num_files; file_index++) {
        int same_file = zupt_compress_paths_same_file(
            output_path, disk_paths[file_index]);
        if (same_file > 0) {
            fprintf(stderr,
                    "Error: archive output and input '%s' are the same file.\n",
                    disk_paths[file_index]);
            return ZUPT_ERR_INVALID;
        }
        if (same_file < 0) {
            fprintf(stderr,
                    "Error: cannot inspect archive output/input identity safely: %s\n",
                    strerror(errno));
            return ZUPT_ERR_IO;
        }
    }
    if (opts->block_size == 0) opts->block_size = opts->dedup ? auto_block_size_dedup(opts->level) : auto_block_size(opts->level);
    if (opts->block_size < 524288) opts->block_size = 524288;

    /* Resolve AUTO codec before compression */
    if (opts->codec_id == ZUPT_CODEC_AUTO)
        opts->codec_id = zupt_resolve_auto_codec();

    FILE *out = NULL;
    zupt_atomic_output_t *atomic_output =
        zupt_atomic_output_open(output_path, &out);
    if (!atomic_output) {
        fprintf(stderr, "Error: Cannot create '%s': %s\n",
                output_path, strerror(errno));
        return ZUPT_ERR_IO;
    }

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
    if (zupt_write_archive_header(out, &hdr) != 0) write_err = 1;

    if (opts->encrypt) {
        zupt_error_t enc_err = write_enc_header(out, &hdr, opts);
        if (enc_err != ZUPT_OK) {
            zupt_atomic_output_finish(atomic_output, 0);
            return enc_err;
        }
    }

    if ((size_t)num_files >
        SIZE_MAX / (sizeof(zupt_index_entry_t) +
                    sizeof(zupt_input_identity_t))) {
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_OVERFLOW;
    }
    zupt_index_entry_t *index = (zupt_index_entry_t *)calloc(
        (size_t)num_files,
        sizeof(zupt_index_entry_t) + sizeof(zupt_input_identity_t));
    if (!index) {
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }
    zupt_input_identity_t *source_identities =
        (zupt_input_identity_t *)(void *)(index + num_files);

    uint64_t total_uncompressed = 0;
    for (int fi = 0; fi < num_files; fi++) {
        zupt_input_identity_t input_identity;
        FILE *inf = zupt_open_regular_input(disk_paths[fi], &input_identity);
        if (!inf) {
            fprintf(stderr, "Error: Cannot read input '%s': %s\n",
                    disk_paths[fi], strerror(errno));
            free(index);
            zupt_atomic_output_finish(atomic_output, 0);
            return ZUPT_ERR_IO;
        }
        int64_t sz = input_identity.size <= INT64_MAX
            ? (int64_t)input_identity.size : -1;
        fclose(inf);
        if (sz < 0 || total_uncompressed > UINT64_MAX - (uint64_t)sz) {
            free(index);
            zupt_atomic_output_finish(atomic_output, 0);
            return sz < 0 ? ZUPT_ERR_IO : ZUPT_ERR_OVERFLOW;
        }
        source_identities[fi] = input_identity;
        strncpy(index[fi].path, arc_paths[fi], ZUPT_MAX_PATH-1);
        index[fi].uncompressed_size = (uint64_t)sz;
        index[fi].first_block_offset = total_uncompressed;
        index[fi].modification_time = input_identity.archive_mtime;
        total_uncompressed += (uint64_t)sz;

        if (!opts->quiet) {
            char sz_s[32]; zupt_format_size((uint64_t)sz, sz_s, sizeof(sz_s));
            fprintf(stderr, "  %s (%s)\n", arc_paths[fi], sz_s);
        }
    }

    if (total_uncompressed > SIZE_MAX) {
        free(index);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_OVERFLOW;
    }
    size_t solid_capacity = total_uncompressed == 0
        ? 1 : (size_t)total_uncompressed;
    uint8_t *solid_buf = (uint8_t*)malloc(solid_capacity);
    if (!solid_buf) {
        free(index);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }

    size_t solid_pos = 0;
    for (int fi = 0; fi < num_files; fi++) {
        zupt_input_identity_t input_identity;
        FILE *inf = zupt_open_regular_input(disk_paths[fi], &input_identity);
        if (!inf) {
            fprintf(stderr, "Error: Cannot reopen input '%s'\n", disk_paths[fi]);
            free(solid_buf); free(index);
            zupt_atomic_output_finish(atomic_output, 0);
            return ZUPT_ERR_IO;
        }
        size_t expected = (size_t)index[fi].uncompressed_size;
        if (!zupt_input_identity_equal(&source_identities[fi],
                                       &input_identity) ||
            fread(solid_buf + solid_pos, 1, expected, inf) != expected ||
            fgetc(inf) != EOF || ferror(inf)) {
            fprintf(stderr, "Error: Input changed while reading '%s'\n",
                    disk_paths[fi]);
            fclose(inf); free(solid_buf); free(index);
            zupt_atomic_output_finish(atomic_output, 0);
            return ZUPT_ERR_IO;
        }
        zupt_input_identity_t final_identity;
        if (!zupt_input_identity_from_stream(inf, &final_identity) ||
            !zupt_input_identity_equal(&input_identity, &final_identity)) {
            fprintf(stderr, "Error: Input changed while reading '%s'\n",
                    disk_paths[fi]);
            fclose(inf); free(solid_buf); free(index);
            zupt_atomic_output_finish(atomic_output, 0);
            return ZUPT_ERR_IO;
        }
        fclose(inf);
        solid_pos += expected;
    }

    uint64_t cum = 0;
    for (int fi = 0; fi < num_files; fi++) {
        uint64_t sz = index[fi].uncompressed_size;
        if (sz > 0) index[fi].content_hash = zupt_xxh64(solid_buf + cum, (size_t)sz, 0);
        cum += sz;
    }

    size_t block_cap = zupt_lzh_bound(opts->block_size) + 512;
    uint8_t *cbuf = (uint8_t*)malloc(block_cap);
    if (!cbuf) {
        free(solid_buf); free(index);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }

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
            if (!enc_pay) {
                free(solid_buf); free(cbuf); free(index);
                zupt_atomic_output_finish(atomic_output, 0);
                return ZUPT_ERR_NOMEM;
            }
            payload = enc_pay;
            payload_size = enc_len;
            bflags |= ZUPT_BFLAG_ENCRYPTED;
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
            free(solid_buf); free(cbuf); free(index);
            zupt_atomic_output_finish(atomic_output, 0);
            return cerr;
        }
        if (opts->has_comment && hdr.comment_offset != 0) {
            int64_t save = ftello(out);
            fseeko(out, 0, SEEK_SET);
            if (zupt_write_archive_header(out, &hdr) != 0) {
                fprintf(stderr, "Error: Failed to update header with comment offset (solid)\n");
                free(solid_buf); free(cbuf); free(index);
                zupt_atomic_output_finish(atomic_output, 0);
                return ZUPT_ERR_IO;
            }
            fseeko(out, save, SEEK_SET);
        }
    }

    /* Write central index (LE serialization) */
    uint64_t index_offset = safe_ftello(out);
    if (num_files < 0 ||
        (size_t)num_files > SIZE_MAX / (ZUPT_MAX_PATH + 128)) {
        free(solid_buf); free(cbuf); free(index);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_OVERFLOW;
    }
    size_t icap = (size_t)num_files * (ZUPT_MAX_PATH + 128);
    uint8_t *ibuf = (uint8_t*)malloc(icap);
    if (!ibuf) {
        free(solid_buf); free(cbuf); free(index);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }

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
    if (!ic) {
        free(ibuf); free(solid_buf); free(cbuf); free(index);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }
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
        if (!enc_idx) {
            free(ic); free(ibuf); free(solid_buf); free(cbuf); free(index);
            zupt_atomic_output_finish(atomic_output, 0);
            return ZUPT_ERR_NOMEM;
        }
        ic_pay = enc_idx;
        ic_plen = enc_len;
        idx_bflags |= ZUPT_BFLAG_ENCRYPTED;
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
    if (zupt_write_footer(out, &ft) != 0) write_err = 1;

    /* F-08 of v2.3.0: archive-integrity-trailer (see compress-flat path). */
    if (!write_err) {
        const zupt_keyring_t *kr = opts->encrypt ? &opts->keyring : NULL;
        if (zupt_format_ait_write(out, &hdr, &ft, kr) != 0) write_err = 1;
    }

    if (zupt_atomic_output_finish(atomic_output, !write_err) != 0)
        write_err = 1;

    if (write_err) {
        fprintf(stderr, "Error: Compression failed; no partial archive was published.\n");
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
    uint8_t serialized[ZUPT_ARCHIVE_HEADER_SIZE];
    if (fread(serialized, 1, sizeof(serialized), f) != sizeof(serialized))
        return ZUPT_ERR_IO;
    deserialize_archive_header(serialized, h);
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
    if (file_size < (int64_t)ZUPT_FOOTER_SIZE) return ZUPT_ERR_CORRUPT;

    /* Try v1.5: footer at EOF-64, AIT at EOF-32 */
    if (file_size >= (int64_t)ZUPT_FOOTER_SIZE + ZUPT_AIT_SIZE) {
        zupt_footer_t cand;
        uint8_t serialized[ZUPT_FOOTER_SIZE];
        fseeko(f, -(int64_t)(ZUPT_FOOTER_SIZE + ZUPT_AIT_SIZE), SEEK_END);
        if (fread(serialized, 1, sizeof(serialized), f) == sizeof(serialized)) {
            deserialize_footer(serialized, &cand);
            if (cand.footer_magic[0]=='Z' && cand.footer_magic[1]=='E' &&
                cand.footer_magic[2]=='N' && cand.footer_magic[3]=='D' &&
                cand.footer_version == 1) {
                if (fread(ait_buf, ZUPT_AIT_SIZE, 1, f) != 1)
                    return ZUPT_ERR_IO;
                *ft = cand;
                *has_ait = 1;
                return ZUPT_OK;
            }
        }
    }

    /* Fall back to v1.4: footer at EOF-32, no AIT */
    uint8_t serialized[ZUPT_FOOTER_SIZE];
    fseeko(f, -(int64_t)ZUPT_FOOTER_SIZE, SEEK_END);
    if (fread(serialized, 1, sizeof(serialized), f) != sizeof(serialized))
        return ZUPT_ERR_IO;
    deserialize_footer(serialized, ft);
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
    uint8_t serialized_footer[ZUPT_FOOTER_SIZE];
    zupt_serialize_archive_header(hdr, buf);
    zupt_serialize_footer(ft, serialized_footer);
    memcpy(buf + ZUPT_ARCHIVE_HEADER_SIZE, serialized_footer, 24);
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
 * Encrypted archives: HMAC-SHA256 with the constant-time-intended tag compare.
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
        /* CT-REQUIRED: use the single constant-time-intended primitive. */
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
    if (!f || !b) return ZUPT_ERR_INVALID;
    memset(b, 0, sizeof(*b));
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

void zupt_legacy_disk_aad_map_free(zupt_legacy_disk_aad_map_t *map) {
    if (!map) return;
    free(map->entries);
    memset(map, 0, sizeof(*map));
}

zupt_error_t zupt_legacy_disk_aad_map_build(
    FILE *stream, uint64_t first_block_offset, uint32_t block_count,
    zupt_legacy_disk_aad_map_t *map) {
    if (!stream || !map || first_block_offset > (uint64_t)INT64_MAX)
        return ZUPT_ERR_INVALID;
    memset(map, 0, sizeof(*map));
    int64_t saved_position = ftello(stream);
    if (saved_position < 0 ||
        fseeko(stream, (int64_t)first_block_offset, SEEK_SET) != 0)
        return ZUPT_ERR_IO;

    zupt_error_t result = ZUPT_OK;
    for (uint64_t sequence = 0; sequence < block_count; sequence++) {
        int64_t signed_offset = ftello(stream);
        if (signed_offset < 0) {
            result = ZUPT_ERR_IO;
            break;
        }
        zupt_block_t block;
        result = read_block(stream, &block);
        if (result != ZUPT_OK) break;
        if (block.block_type == ZUPT_BLOCK_DATA) {
            if (map->count == map->capacity) {
                size_t new_capacity = map->capacity ? map->capacity * 2u : 64u;
                if (new_capacity < map->capacity ||
                    new_capacity > SIZE_MAX / sizeof(*map->entries)) {
                    free(block.payload);
                    result = ZUPT_ERR_OVERFLOW;
                    break;
                }
                if (new_capacity > block_count) new_capacity = block_count;
                zupt_legacy_disk_aad_entry_t *new_entries =
                    (zupt_legacy_disk_aad_entry_t *)realloc(
                        map->entries,
                        new_capacity * sizeof(*map->entries));
                if (!new_entries) {
                    free(block.payload);
                    result = ZUPT_ERR_NOMEM;
                    break;
                }
                map->entries = new_entries;
                map->capacity = new_capacity;
            }
            map->entries[map->count].offset = (uint64_t)signed_offset;
            map->entries[map->count].aad_seq = sequence;
            map->count++;
        } else if (block.block_type != ZUPT_BLOCK_DEDUP_REF) {
            result = ZUPT_ERR_CORRUPT;
        }
        free(block.payload);
        if (result != ZUPT_OK) break;
    }
    if (fseeko(stream, saved_position, SEEK_SET) != 0 && result == ZUPT_OK)
        result = ZUPT_ERR_IO;
    if (result != ZUPT_OK) zupt_legacy_disk_aad_map_free(map);
    return result;
}

int zupt_legacy_disk_aad_map_lookup(
    const zupt_legacy_disk_aad_map_t *map, uint64_t offset,
    uint64_t *aad_seq) {
    if (!map || !aad_seq) return 0;
    size_t left = 0;
    size_t right = map->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2u;
        uint64_t candidate = map->entries[middle].offset;
        if (candidate < offset)
            left = middle + 1u;
        else
            right = middle;
    }
    if (left >= map->count || map->entries[left].offset != offset) return 0;
    *aad_seq = map->entries[left].aad_seq;
    return 1;
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
            if (zupt_internal_verbose(opts)) {
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
            if (zupt_internal_verbose(opts)) {
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
            if (zupt_internal_verbose(opts)) {
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
        iter = zupt_le32_get(eb.payload + 49);
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
        iter = zupt_le32_get(eb.payload + 48);
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
    *ents = NULL;
    *n = 0;
    size_t p = 0; uint64_t count;
    int vn = zupt_decode_varint(buf+p, blen-p, &count);
    if (vn < 0) return ZUPT_ERR_CORRUPT;
    p += (size_t)vn;
    if (count > ZUPT_MAX_FILES) return ZUPT_ERR_OVERFLOW;
    if (count > (uint64_t)((blen - p) / ZUPT_MIN_INDEX_ENTRY_BYTES))
        return ZUPT_ERR_CORRUPT;
    /* Defense for 32-bit platforms: count * sizeof(entry) must fit in size_t.
     * Each entry is ~4 KB; on 32-bit, ~1M entries already exceeds 4 GiB. */
    if (count > (uint64_t)(SIZE_MAX / sizeof(zupt_index_entry_t))) {
        return ZUPT_ERR_OVERFLOW;
    }
    if (count > (uint64_t)(ZUPT_MAX_INDEX_ALLOC_BYTES /
                           sizeof(zupt_index_entry_t)))
        return ZUPT_ERR_OVERFLOW;
    if (count == 0)
        return p == blen ? ZUPT_OK : ZUPT_ERR_CORRUPT;
    zupt_index_entry_t *parsed =
        (zupt_index_entry_t*)calloc((size_t)count, sizeof(*parsed));
    if (!parsed) return ZUPT_ERR_NOMEM;

    for (uint64_t i = 0; i < count; i++) {
        zupt_index_entry_t *e = &parsed[i];
        uint64_t plen;
        vn = zupt_decode_varint(buf+p, blen-p, &plen);
        if (vn<0) { free(parsed); return ZUPT_ERR_CORRUPT; }
        /* SECURITY: overflow-safe bound. The decoder consumes at most blen-p
         * bytes so p+vn<=blen and blen-p-vn cannot underflow. The previous
         * check `p+vn+plen>blen` wrapped around for an attacker-supplied
         * ~2^64 plen, passed, then drove an OOB memcpy of ZUPT_MAX_PATH-1
         * bytes past the index buffer. */
        if (plen > (uint64_t)(blen - p - (size_t)vn)) { free(parsed); return ZUPT_ERR_CORRUPT; }
        p += (size_t)vn;
        if (plen == 0 || plen >= ZUPT_MAX_PATH ||
            memchr(buf + p, '\0', (size_t)plen) != NULL) {
            free(parsed);
            return ZUPT_ERR_CORRUPT;
        }
        memcpy(e->path, buf+p, (size_t)plen); e->path[plen]='\0'; p += (size_t)plen;
        if (zupt_path_has_unsafe_text(e->path)) {
            free(parsed);
            return ZUPT_ERR_CORRUPT;
        }

        if (blen - p < 44) { free(parsed); return ZUPT_ERR_CORRUPT; }
        e->uncompressed_size = index_get_u64(buf+p); p+=8;
        e->compressed_size   = index_get_u64(buf+p); p+=8;
        e->modification_time = index_get_u64(buf+p); p+=8;
        e->content_hash      = index_get_u64(buf+p); p+=8;
        e->first_block_offset= index_get_u64(buf+p); p+=8;
        uint64_t bc;
        vn = zupt_decode_varint(buf+p, blen-p, &bc);
        if (vn<0 || bc > UINT32_MAX) { free(parsed); return ZUPT_ERR_CORRUPT; }
        p += (size_t)vn; e->block_count = (uint32_t)bc;
        if (blen - p < 4) { free(parsed); return ZUPT_ERR_CORRUPT; }
        e->attributes = index_get_u32(buf+p); p+=4;
    }
    if (p != blen) { free(parsed); return ZUPT_ERR_CORRUPT; }
    const char **paths = (const char **)calloc((size_t)count, sizeof(*paths));
    if (!paths) { free(parsed); return ZUPT_ERR_NOMEM; }
    for (uint64_t i = 0; i < count; i++) paths[i] = parsed[i].path;
    zupt_error_t path_error = zupt_validate_archive_destinations(
        paths, (int)count, 0);
    free(paths);
    if (path_error != ZUPT_OK) {
        free(parsed);
        return path_error;
    }
    *n = (int)count;
    *ents = parsed;
    return ZUPT_OK;
}

/* Disk archives through v5.2.1 encoded their single-entry count and block
 * count as fixed little-endian integers.  Keep that published format readable
 * while all new disk archives use the canonical varint index. */
static zupt_error_t parse_legacy_disk_index(
        const uint8_t *buf, size_t blen, zupt_index_entry_t **ents, int *n) {
    *ents = NULL;
    *n = 0;
    if (!buf || blen < 4 || index_get_u32(buf) != 1) return ZUPT_ERR_CORRUPT;
    size_t p = 4;
    uint64_t path_length = 0;
    int vn = zupt_decode_varint(buf + p, blen - p, &path_length);
    if (vn < 0 || path_length == 0 || path_length >= ZUPT_MAX_PATH ||
        path_length > blen - p - (size_t)vn)
        return ZUPT_ERR_CORRUPT;
    p += (size_t)vn;
    if (memchr(buf + p, '\0', (size_t)path_length) ||
        blen - p - (size_t)path_length != 48)
        return ZUPT_ERR_CORRUPT;

    zupt_index_entry_t *entry =
        (zupt_index_entry_t *)calloc(1, sizeof(*entry));
    if (!entry) return ZUPT_ERR_NOMEM;
    memcpy(entry->path, buf + p, (size_t)path_length);
    entry->path[path_length] = '\0';
    if (zupt_path_has_unsafe_text(entry->path)) {
        free(entry);
        return ZUPT_ERR_CORRUPT;
    }
    p += (size_t)path_length;
    entry->uncompressed_size = index_get_u64(buf + p); p += 8;
    entry->compressed_size = index_get_u64(buf + p); p += 8;
    entry->modification_time = index_get_u64(buf + p); p += 8;
    entry->content_hash = index_get_u64(buf + p); p += 8;
    entry->first_block_offset = index_get_u64(buf + p); p += 8;
    entry->block_count = index_get_u32(buf + p); p += 4;
    entry->attributes = index_get_u32(buf + p); p += 4;
    if (p != blen) { free(entry); return ZUPT_ERR_CORRUPT; }
    *ents = entry;
    *n = 1;
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

    /* Refuse integrity downgrades by default.  This check deliberately does
     * not trust ZUPT_FLAG_ENCRYPTED: an attacker removing the AIT could also
     * clear that unauthenticated header bit and forge a legacy plaintext
     * footer/index.  Old no-AIT archives remain readable only through an
     * explicit, narrowly named compatibility opt-in. */
    if (!has_ait && !zupt_internal_legacy_no_ait_allowed(opts)) {
        fprintf(stderr,
                "Error: archive has no archive-integrity trailer.\n"
                "       Refusing an unauthenticated legacy layout by default;\n"
                "       use --allow-legacy-no-ait only for a trusted old archive.\n");
        return ZUPT_ERR_AUTH_FAIL;
    }

    if ((hdr->global_flags & ZUPT_FLAG_AUTH_DEDUP_REFS) != 0) {
        const uint32_t required = ZUPT_FLAG_ENCRYPTED | ZUPT_FLAG_DEDUP |
                                  ZUPT_FLAG_AAD_SEQ | ZUPT_FLAG_AAD_PREFACE;
        if ((hdr->global_flags & required) != required)
            return ZUPT_ERR_CORRUPT;
    }
    if ((hdr->global_flags & ZUPT_FLAG_AAD_PREFACE) != 0 &&
        (hdr->global_flags & (ZUPT_FLAG_ENCRYPTED | ZUPT_FLAG_AAD_SEQ)) !=
            (ZUPT_FLAG_ENCRYPTED | ZUPT_FLAG_AAD_SEQ))
        return ZUPT_ERR_CORRUPT;
    if ((hdr->global_flags & ZUPT_FLAG_DISK_CONTENT_HASH) != 0 &&
        (hdr->global_flags & ZUPT_FLAG_DISK_IMAGE) == 0)
        return ZUPT_ERR_CORRUPT;

    err = read_enc_header(f, hdr, opts);
    if (err != ZUPT_OK) return err;

    /* F-08 of v2.3.0: verify the archive-integrity-trailer.
     *
     * For encrypted archives, the AIT is HMAC-SHA256(mac_key, hdr || ft[0..23])
     * and MUST authenticate before we read any further. For plaintext archives,
     * the AIT is XXH64 best-effort.
     *
     * A legacy archive without AIT reaches this point only after the caller's
     * explicit --allow-legacy-no-ait opt-in.  The warning below applies to
     * plaintext and encrypted legacy layouts alike because the unauthenticated
     * ENCRYPTED bit cannot safely decide whether a trailer was stripped. */
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
                if (zupt_internal_verbose(opts)) {
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
    } else {
        fprintf(stderr,
                "Warning: explicitly accepting a trusted legacy archive without\n"
                "         an archive-integrity trailer; metadata is unauthenticated.\n");
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
    const zupt_keyring_t *index_keyring = &opts->keyring;
    if ((hdr->global_flags & (ZUPT_FLAG_DISK_IMAGE | ZUPT_FLAG_ENCRYPTED)) ==
            (ZUPT_FLAG_DISK_IMAGE | ZUPT_FLAG_ENCRYPTED) &&
        !(hdr->global_flags & ZUPT_FLAG_DISK_CONTENT_HASH)) {
        /* Legacy disk writers left the index plaintext. Preserve read
         * compatibility, but new disk archives set DISK_CONTENT_HASH and
         * authenticate this block like every other encrypted payload. */
        index_keyring = NULL;
        fprintf(stderr, "Warning: legacy encrypted disk index is not authenticated.\n");
    }
    err = decompress_block(&ib, index_keyring, UINT64_MAX, &id, &idlen);
    free(ib.payload);
    if (err != ZUPT_OK) return err;

    if ((hdr->global_flags & ZUPT_FLAG_DISK_IMAGE) &&
        !(hdr->global_flags & ZUPT_FLAG_DISK_CONTENT_HASH))
        err = parse_legacy_disk_index(id, idlen, entries, num_entries);
    else
        err = parse_index(id, idlen, entries, num_entries);
    free(id);
    return err;
}

zupt_error_t zupt_open_archive_internal(FILE *stream, zupt_options_t *opts,
                                        zupt_archive_header_t *header,
                                        zupt_footer_t *footer,
                                        zupt_index_entry_t **entries,
                                        int *num_entries) {
    return open_archive(stream, opts, header, footer, entries, num_entries);
}

static uint64_t archive_data_aad_seq(uint32_t global_flags, int entry_index,
                                     uint64_t block_index) {
    /* Disk writers, including 5.2.1, use one linear sequence across DATA and
     * DEDUP_REF frames.  Legacy file-archive dedup used sequence zero; new file
     * archives bind file+block position. */
    if ((global_flags & ZUPT_FLAG_DISK_IMAGE) != 0)
        return block_index;
    if ((global_flags & ZUPT_FLAG_DEDUP) != 0 &&
        (global_flags & ZUPT_FLAG_AUTH_DEDUP_REFS) == 0)
        return 0;
    return (((uint64_t)(entry_index + 1)) << 32) | block_index;
}

/* ═══════════════════════════════════════════════════════════════════
 * LIST
 * ═══════════════════════════════════════════════════════════════════ */

zupt_error_t zupt_list_archive(const char *arc, zupt_options_t *opts) {
    FILE *f = zupt_fopen_path(arc, "rb");
    if (!f) { fprintf(stderr, "Error: Cannot open '%s'\n", arc); return ZUPT_ERR_IO; }

    zupt_archive_header_t hdr; zupt_footer_t ft;
    zupt_index_entry_t *ents; int n;
    zupt_error_t err = open_archive(f, opts, &hdr, &ft, &ents, &n);
    if (err != ZUPT_OK) { fclose(f); return err; }

    printf("\n ZUPT archive: %s\n", arc);
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
    FILE *f = zupt_fopen_path(arc, "rb");
    if (!f) { fprintf(stderr, "Error: Cannot open '%s'\n", arc); return ZUPT_ERR_IO; }

    zupt_archive_header_t hdr; zupt_footer_t ft;
    zupt_index_entry_t *ents; int n;
    zupt_error_t err = open_archive(f, opts, &hdr, &ft, &ents, &n);
    if (err != ZUPT_OK) { fclose(f); fprintf(stderr, "Error: %s\n", zupt_strerror(err)); return err; }

    int ok=0, fail=0;
    uint64_t total_extracted = 0;
    time_t start = time(NULL);

    int is_solid = (hdr.global_flags & ZUPT_FLAG_SOLID) != 0;

    if (is_solid) {
        uint64_t total_size = 0;
        for (int i = 0; i < n; i++) {
            if (ents[i].uncompressed_size > UINT64_MAX - total_size) {
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

        uint8_t *solid_buf =
            (uint8_t*)malloc(total_size == 0 ? 1 : (size_t)total_size);
        if (!solid_buf) { free(ents); fclose(f); return ZUPT_ERR_NOMEM; }

        fseeko(f, ZUPT_ARCHIVE_HEADER_SIZE, SEEK_SET);

        if (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) {
            zupt_block_t enc_blk = {0};
            err = read_block(f, &enc_blk);
            if (err != ZUPT_OK) { free(solid_buf); free(ents); fclose(f); return err; }
            free(enc_blk.payload);
        }

        size_t solid_pos = 0;
        uint64_t block_seq = 0;
        int dec_error = 0;
        uint64_t solid_data_end =
            hdr.comment_offset != 0 ? hdr.comment_offset : ft.index_offset;

        while (!dec_error) {
            int64_t frame_position = ftello(f);
            if (frame_position < 0) {
                dec_error = 1;
                break;
            }
            if ((uint64_t)frame_position == solid_data_end) break;
            if ((uint64_t)frame_position > solid_data_end) {
                dec_error = 1;
                break;
            }
            zupt_block_t blk;
            err = read_block(f, &blk);
            if (err != ZUPT_OK) { dec_error = 1; break; }
            if (blk.block_type != ZUPT_BLOCK_DATA) {
                free(blk.payload);
                dec_error = 1;
                break;
            }

            uint8_t *dec = NULL; size_t dlen = 0;
            /* Solid mode uses synthetic fi=0 (AAD = (1<<32) | block_seq) */
            uint64_t aad_seq = ((uint64_t)1 << 32) | block_seq;
            err = decompress_block(&blk, &opts->keyring, aad_seq, &dec, &dlen);
            free(blk.payload);
            if (err != ZUPT_OK) {
                fprintf(stderr, "  Solid block %llu decompression failed: %s\n",
                        (unsigned long long)block_seq, zupt_strerror(err));
                dec_error = 1; break;
            }

            if (dlen > (size_t)total_size - solid_pos || (dlen > 0 && !dec)) {
                free(dec);
                dec_error = 1;
                break;
            }
            if (dlen > 0) memcpy(solid_buf + solid_pos, dec, dlen);
            solid_pos += dlen;
            free(dec);
            block_seq++;
        }

        int64_t solid_end = ftello(f);
        uint64_t solid_metadata_blocks =
            1u + (hdr.comment_offset != 0 ? 1u : 0u);
        if (dec_error || solid_pos != (size_t)total_size ||
            ft.total_blocks < solid_metadata_blocks ||
            block_seq != ft.total_blocks - solid_metadata_blocks ||
            solid_end < 0 || (uint64_t)solid_end != solid_data_end) {
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
            uint64_t off = e->first_block_offset;
            uint64_t sz = e->uncompressed_size;
            /* SECURITY: overflow-safe bound. off and sz are both attacker-
             * controlled 64-bit index fields; the previous `off+sz<=total_size`
             * wrapped on overflow, letting solid_buf+off point far out of
             * bounds for an arbitrary-offset OOB heap read. */
            if (off > total_size || sz > total_size - off) {
                fprintf(stderr, "  Invalid offset: %s\n", e->path); fail++;
                continue;
            }
            uint64_t ck = sz > 0 ?
                zupt_xxh64(solid_buf + off, (size_t)sz, 0) : 0;
            if (ck != e->content_hash) {
                fprintf(stderr, "  Checksum fail: %s\n", e->path);
                fail++;
                continue;
            }

            char out_path[ZUPT_MAX_PATH + 256];
            zupt_output_file_t output;
            if (!zupt_safe_fopen_output(dir, e->path, out_path,
                                        sizeof(out_path), &output)) {
                fprintf(stderr, "  Error: cannot create %s\n", out_path);
                fail++;
                continue;
            }
            if ((sz > 0 && fwrite(solid_buf + off, 1, (size_t)sz,
                                  output.stream) != (size_t)sz) ||
                zupt_finish_output(&output, 1, 0) != 0) {
                fprintf(stderr, "Error: write failed (disk full?) for %s\n", e->path);
                if (output.stream) zupt_finish_output(&output, 0, 0);
                fail++;
                continue;
            }
            total_extracted += sz;
            ok++;

            if (zupt_internal_verbose(opts)) {
                char sz_s[16]; zupt_format_size(sz, sz_s, sizeof(sz_s));
                fprintf(stderr, "  %s (%s)\n", e->path, sz_s);
            }
        }

        free(solid_buf);
    } else {
        /* ─── NON-SOLID EXTRACTION ─── */
        int legacy_encrypted_disk_dedup =
            (hdr.global_flags & ZUPT_FLAG_DISK_IMAGE) != 0 &&
            (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) != 0 &&
            (hdr.global_flags & ZUPT_FLAG_DEDUP) != 0 &&
            (hdr.global_flags & ZUPT_FLAG_AUTH_DEDUP_REFS) == 0;
        zupt_legacy_disk_aad_map_t legacy_aad_map = {0};
        if (legacy_encrypted_disk_dedup) {
            if (n != 1) {
                free(ents);
                fclose(f);
                return ZUPT_ERR_CORRUPT;
            }
            err = zupt_legacy_disk_aad_map_build(
                f, ents[0].first_block_offset, ents[0].block_count,
                &legacy_aad_map);
            if (err != ZUPT_OK) {
                free(ents);
                fclose(f);
                return err;
            }
        }

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
            zupt_output_file_t output;
            if (!zupt_safe_fopen_output(dir, e->path, out_path,
                                        sizeof(out_path), &output)) {
                fprintf(stderr, "  Error: cannot create %s\n", out_path);
                fail++;
                continue;
            }
            FILE *of = output.stream;
            uint64_t file_extracted = 0;
            uint64_t file_hash = 0;

            if (zupt_internal_verbose(opts)) {
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
                        if (blk.block_type == ZUPT_BLOCK_DEDUP_REF) {
                            /* Flush pending workers first to maintain order */
                            for (int pi = 0; pi < npending; pi++) {
                                zpar_slot_t *s = zpar_wait_slot(pctx, pending_slots[pi]);
                                if (!s || s->error != ZUPT_OK) { berr = 1; }
                                else if (s->output && s->output_len > 0) {
                                    if (!zupt_write_verified_chunk(of, s->output,
                                            s->output_len, e->uncompressed_size,
                                            &file_extracted, &file_hash)) berr = 1;
                                }
                                zpar_release_slot(pctx, pending_slots[pi]);
                            }
                            npending = 0;
                            if (berr) { free(blk.payload); break; }

                            uint64_t ref_off = 0, referenced_aad_seq = 0;
                            int64_t cur2 = ftello(f);
                            int require_authentication =
                                (hdr.global_flags & ZUPT_FLAG_AUTH_DEDUP_REFS) != 0;
                            err = zupt_dedup_read_ref(
                                &blk, &opts->keyring, require_authentication,
                                require_authentication
                                    ? archive_data_aad_seq(
                                          hdr.global_flags, i, decomp_seq)
                                    : 0,
                                &ref_off, &referenced_aad_seq);
                            if (err == ZUPT_OK && legacy_encrypted_disk_dedup &&
                                !zupt_legacy_disk_aad_map_lookup(
                                    &legacy_aad_map, ref_off,
                                    &referenced_aad_seq))
                                err = ZUPT_ERR_CORRUPT;
                            /* Defense: ref_off must be earlier than current position
                             * (dedup refs always point to previously-emitted blocks)
                             * and must be within the file. */
                            if (err != ZUPT_OK || cur2 < 0 ||
                                ref_off >= (uint64_t)cur2 ||
                                fseeko(f, (int64_t)ref_off, SEEK_SET) != 0) {
                                free(blk.payload);
                                berr = 1; break;
                            }
                            zupt_block_t ref_blk;
                            err = read_block(f, &ref_blk);
                            if (fseeko(f, cur2, SEEK_SET) != 0 && err == ZUPT_OK)
                                err = ZUPT_ERR_IO;
                            if (err != ZUPT_OK) {
                                free(blk.payload); berr = 1; break;
                            }
                            /* Defense: refs must point to data blocks, not other refs.
                             * Prevents amplification + infinite loop attacks. */
                            if (ref_blk.block_type != ZUPT_BLOCK_DATA ||
                                ref_blk.uncompressed_size != blk.uncompressed_size ||
                                ref_blk.checksum != blk.checksum) {
                                free(blk.payload); free(ref_blk.payload);
                                berr = 1; break;
                            }
                            free(blk.payload);
                            uint8_t *rdec; size_t rdlen;
                            err = decompress_block(&ref_blk, &opts->keyring,
                                                   referenced_aad_seq,
                                                   &rdec, &rdlen);
                            free(ref_blk.payload);
                            if (err != ZUPT_OK) { berr = 1; break; }
                            if (!zupt_write_verified_chunk(of, rdec, rdlen,
                                    e->uncompressed_size, &file_extracted,
                                    &file_hash)) berr = 1;
                            free(rdec);
                            blocks_remaining--;
                            decomp_seq++;
                            continue;
                        }

                        if (blk.block_type != ZUPT_BLOCK_DATA) {
                            free(blk.payload);
                            berr = 1;
                            break;
                        }

                        /* Legacy file-archive dedup used sequence zero. New
                         * archives bind each DATA frame to this position. */
                        uint64_t aad_seq = archive_data_aad_seq(
                            hdr.global_flags, i, decomp_seq);
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
                            if (!zupt_write_verified_chunk(of, s->output,
                                    s->output_len, e->uncompressed_size,
                                    &file_extracted, &file_hash)) berr = 1;
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
                    if (blk.block_type == ZUPT_BLOCK_DEDUP_REF) {
                        uint64_t ref_off = 0, referenced_aad_seq = 0;
                        int64_t cur = ftello(f);
                        int require_authentication =
                            (hdr.global_flags & ZUPT_FLAG_AUTH_DEDUP_REFS) != 0;
                        err = zupt_dedup_read_ref(
                            &blk, &opts->keyring, require_authentication,
                            require_authentication
                                ? archive_data_aad_seq(
                                      hdr.global_flags, i, (uint64_t)b)
                                : 0,
                            &ref_off, &referenced_aad_seq);
                        if (err == ZUPT_OK && legacy_encrypted_disk_dedup &&
                            !zupt_legacy_disk_aad_map_lookup(
                                &legacy_aad_map, ref_off,
                                &referenced_aad_seq))
                            err = ZUPT_ERR_CORRUPT;
                        if (err != ZUPT_OK || cur < 0 ||
                            ref_off >= (uint64_t)cur ||
                            fseeko(f, (int64_t)ref_off, SEEK_SET) != 0) {
                            free(blk.payload); berr=1; break;
                        }
                        zupt_block_t ref_blk;
                        err = read_block(f, &ref_blk);
                        if (fseeko(f, cur, SEEK_SET) != 0 && err == ZUPT_OK)
                            err = ZUPT_ERR_IO;
                        if (err != ZUPT_OK) {
                            free(blk.payload); berr=1; break;
                        }
                        if (ref_blk.block_type != ZUPT_BLOCK_DATA ||
                            ref_blk.uncompressed_size != blk.uncompressed_size ||
                            ref_blk.checksum != blk.checksum) {
                            free(blk.payload); free(ref_blk.payload);
                            berr=1; break;
                        }
                        free(blk.payload);
                        uint8_t *dec = NULL; size_t dlen = 0;
                        err = decompress_block(&ref_blk, &opts->keyring,
                                               referenced_aad_seq,
                                               &dec, &dlen);
                        free(ref_blk.payload);
                        if (err != ZUPT_OK) { berr=1; break; }
                        if (!zupt_write_verified_chunk(of, dec, dlen,
                                e->uncompressed_size, &file_extracted,
                                &file_hash)) berr = 1;
                        free(dec);
                        continue;
                    }

                    if (blk.block_type != ZUPT_BLOCK_DATA) {
                        free(blk.payload);
                        berr = 1;
                        break;
                    }

                    uint8_t *dec = NULL; size_t dlen = 0;
                    uint64_t aad_seq = archive_data_aad_seq(
                        hdr.global_flags, i, (uint64_t)b);
                    err = decompress_block(&blk, &opts->keyring, aad_seq, &dec, &dlen);
                    free(blk.payload);
                    if (err != ZUPT_OK) { berr=1; break; }
                    if (!zupt_write_verified_chunk(of, dec, dlen,
                            e->uncompressed_size, &file_extracted,
                            &file_hash)) berr = 1;
                    free(dec);
                }
            }

file_done:
            ;
            int require_content_hash =
                !(hdr.global_flags & ZUPT_FLAG_DISK_IMAGE) ||
                (hdr.global_flags & ZUPT_FLAG_DISK_CONTENT_HASH);
            if (!berr && (file_extracted != e->uncompressed_size ||
                          (require_content_hash &&
                           file_hash != e->content_hash))) {
                fprintf(stderr, "  Size or checksum mismatch: %s\n", e->path);
                berr = 1;
            }
            if (zupt_finish_output(&output, !berr, 0) != 0) berr = 1;
            if (berr) {
                fail++;
            } else {
                total_extracted += file_extracted;
                ok++;
            }
        }

        if (pctx) zpar_destroy(pctx);
        zupt_legacy_disk_aad_map_free(&legacy_aad_map);
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
        fputs("\n  Comment: ", stderr);
        zupt_print_terminal_safe_text(stderr, opts->comment);
        fputc('\n', stderr);
    }

    free(ents); fclose(f);
    return fail>0 ? ZUPT_ERR_CORRUPT : ZUPT_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * TEST
 * ═══════════════════════════════════════════════════════════════════ */

zupt_error_t zupt_test_archive_stream(FILE *f, zupt_options_t *opts) {
    if (!f || !opts) return ZUPT_ERR_INVALID;
    if (fseeko(f, 0, SEEK_SET) != 0) return ZUPT_ERR_IO;
    zupt_archive_header_t hdr; zupt_footer_t ft;
    zupt_index_entry_t *ents; int n;
    zupt_error_t err = open_archive(f, opts, &hdr, &ft, &ents, &n);
    if (err != ZUPT_OK) {
        fprintf(stderr, "Error: %s\n", zupt_strerror(err));
        return err;
    }

    int pass=0, fail=0;
    int is_solid = (hdr.global_flags & ZUPT_FLAG_SOLID) != 0;

    if (is_solid) {
        uint64_t total_size = 0;
        for (int i = 0; i < n; i++) {
            if (ents[i].uncompressed_size > UINT64_MAX - total_size) {
                fprintf(stderr, "  Error: solid stream size overflow\n");
                free(ents); return ZUPT_ERR_OVERFLOW;
            }
            total_size += ents[i].uncompressed_size;
        }

        if (total_size > (uint64_t)4 * 1024 * 1024 * 1024) {
            fprintf(stderr, "  Error: solid stream too large for test\n");
            free(ents); return ZUPT_ERR_OVERFLOW;
        }
        if (total_size > (uint64_t)SIZE_MAX) {
            fprintf(stderr,
                    "  Error: solid stream exceeds size_t on this platform\n");
            free(ents); return ZUPT_ERR_OVERFLOW;
        }

        uint8_t *solid_buf =
            (uint8_t*)malloc(total_size == 0 ? 1 : (size_t)total_size);
        if (!solid_buf) { free(ents); return ZUPT_ERR_NOMEM; }

        fseeko(f, ZUPT_ARCHIVE_HEADER_SIZE, SEEK_SET);
        if (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) {
            zupt_block_t enc_blk;
            err = read_block(f, &enc_blk);
            if (err == ZUPT_OK) free(enc_blk.payload);
        }

        size_t solid_pos = 0;
        uint64_t block_seq = 0;
        int blocks_ok = 0, blocks_fail = 0;
        uint64_t solid_data_end =
            hdr.comment_offset != 0 ? hdr.comment_offset : ft.index_offset;

        while (blocks_fail == 0) {
            int64_t frame_position = ftello(f);
            if (frame_position < 0) {
                blocks_fail++;
                break;
            }
            if ((uint64_t)frame_position == solid_data_end) break;
            if ((uint64_t)frame_position > solid_data_end) {
                blocks_fail++;
                break;
            }
            zupt_block_t blk;
            err = read_block(f, &blk);
            if (err != ZUPT_OK) { blocks_fail++; break; }
            if (blk.block_type != ZUPT_BLOCK_DATA) {
                free(blk.payload);
                blocks_fail++;
                break;
            }

            uint8_t *dec = NULL; size_t dlen = 0;
            /* Solid mode AAD: synthetic fi=0 */
            uint64_t aad_seq = ((uint64_t)1 << 32) | block_seq;
            err = decompress_block(&blk, &opts->keyring, aad_seq, &dec, &dlen);
            free(blk.payload);
            if (err != ZUPT_OK) {
                fprintf(stderr, "  Block %llu: FAIL (%s)\n",
                        (unsigned long long)block_seq, zupt_strerror(err));
                blocks_fail++; break;
            }

            if (dlen > (size_t)total_size - solid_pos || (dlen > 0 && !dec)) {
                free(dec);
                blocks_fail++;
                break;
            }
            if (dlen > 0) memcpy(solid_buf + solid_pos, dec, dlen);
            solid_pos += dlen;
            free(dec);
            blocks_ok++;
            block_seq++;
        }

        int64_t solid_end = ftello(f);
        uint64_t solid_metadata_blocks =
            1u + (hdr.comment_offset != 0 ? 1u : 0u);
        if (blocks_fail == 0 &&
            (solid_pos != (size_t)total_size ||
             ft.total_blocks < solid_metadata_blocks ||
             block_seq != ft.total_blocks - solid_metadata_blocks ||
             solid_end < 0 || (uint64_t)solid_end != solid_data_end))
            blocks_fail++;

        if (blocks_fail > 0) {
            fprintf(stderr, "  Solid stream: %d blocks OK, %d failed\n", blocks_ok, blocks_fail);
            free(solid_buf); free(ents);
            return ZUPT_ERR_CORRUPT;
        }

        for (int i = 0; i < n; i++) {
            zupt_index_entry_t *e = &ents[i];
            uint64_t off = e->first_block_offset;
            uint64_t sz = e->uncompressed_size;
            int fok = 1;

            /* Overflow-safe bound: off+sz can wrap (both are attacker-controlled
             * index fields), so `off + sz > total_size` could pass falsely and
             * feed a wild pointer / oversized length to zupt_xxh64. Match the
             * hardened extract path. */
            if (off > (uint64_t)total_size || sz > (uint64_t)total_size - off) {
                fok = 0;
            } else if (sz > 0) {
                uint64_t ck = zupt_xxh64(solid_buf + off, (size_t)sz, 0);
                if (ck != e->content_hash) fok = 0;
            }

            if (fok) {
                if (zupt_internal_verbose(opts)) fprintf(stderr, "  OK: %s\n", e->path);
                pass++;
            } else {
                fprintf(stderr, "  FAIL: %s (checksum mismatch)\n", e->path);
                fail++;
            }
        }

        free(solid_buf);
    } else {
        int legacy_encrypted_disk_dedup =
            (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) != 0 &&
            (hdr.global_flags & ZUPT_FLAG_DISK_IMAGE) != 0 &&
            (hdr.global_flags & ZUPT_FLAG_DEDUP) != 0 &&
            (hdr.global_flags & ZUPT_FLAG_AUTH_DEDUP_REFS) == 0;
        zupt_legacy_disk_aad_map_t legacy_aad_map = {0};
        if (legacy_encrypted_disk_dedup) {
            if (n != 1) {
                free(ents);
                return ZUPT_ERR_CORRUPT;
            }
            err = zupt_legacy_disk_aad_map_build(
                f, ents[0].first_block_offset, ents[0].block_count,
                &legacy_aad_map);
            if (err != ZUPT_OK) {
                free(ents);
                return err;
            }
        }
        for (int i = 0; i < n; i++) {
            zupt_index_entry_t *e = &ents[i];
            fseeko(f, (int64_t)e->first_block_offset, SEEK_SET);
            int fok = 1;
            uint64_t tested_size = 0;
            uint64_t tested_hash = 0;
            for (uint32_t b = 0; b < e->block_count; b++) {
                zupt_block_t blk;
                err = read_block(f, &blk);
                if (err != ZUPT_OK) { fok=0; break; }
                uint8_t *dec = NULL; size_t dlen = 0;
                uint64_t aad_seq = archive_data_aad_seq(
                    hdr.global_flags, i, (uint64_t)b);

                if (blk.block_type == ZUPT_BLOCK_DEDUP_REF) {
                    uint64_t ref_offset = 0, referenced_aad_seq = 0;
                    int require_authentication =
                        (hdr.global_flags & ZUPT_FLAG_AUTH_DEDUP_REFS) != 0;
                    err = zupt_dedup_read_ref(&blk, &opts->keyring,
                                              require_authentication,
                                              require_authentication
                                                  ? aad_seq : 0,
                                              &ref_offset,
                                              &referenced_aad_seq);
                    if (err == ZUPT_OK && legacy_encrypted_disk_dedup &&
                        !zupt_legacy_disk_aad_map_lookup(
                            &legacy_aad_map, ref_offset,
                            &referenced_aad_seq))
                        err = ZUPT_ERR_CORRUPT;
                    int64_t resume = ftello(f);
                    if (err != ZUPT_OK) {
                        free(blk.payload);
                        fok = 0;
                        break;
                    }
                    if (resume < 0 ||
                        ref_offset >= (uint64_t)resume ||
                        fseeko(f, (int64_t)ref_offset, SEEK_SET) != 0) {
                        free(blk.payload);
                        err = ZUPT_ERR_CORRUPT;
                        fok = 0;
                        break;
                    }
                    zupt_block_t referenced;
                    err = read_block(f, &referenced);
                    if (fseeko(f, resume, SEEK_SET) != 0 && err == ZUPT_OK)
                        err = ZUPT_ERR_IO;
                    if (err == ZUPT_OK &&
                        (referenced.block_type != ZUPT_BLOCK_DATA ||
                         referenced.uncompressed_size != blk.uncompressed_size ||
                         referenced.checksum != blk.checksum))
                        err = ZUPT_ERR_CORRUPT;
                    free(blk.payload);
                    if (err == ZUPT_OK)
                        err = decompress_block(&referenced, &opts->keyring,
                                               referenced_aad_seq,
                                               &dec, &dlen);
                    free(referenced.payload);
                } else if (blk.block_type == ZUPT_BLOCK_DATA) {
                    err = decompress_block(&blk, &opts->keyring, aad_seq,
                                           &dec, &dlen);
                    free(blk.payload);
                } else {
                    free(blk.payload);
                    err = ZUPT_ERR_CORRUPT;
                }
                if (err != ZUPT_OK) { fok=0; break; }
                if (tested_size > e->uncompressed_size ||
                    (uint64_t)dlen > e->uncompressed_size - tested_size) {
                    free(dec);
                    err = ZUPT_ERR_OVERFLOW;
                    fok = 0;
                    break;
                }
                tested_hash = zupt_xxh64(dec, dlen, tested_hash);
                tested_size += dlen;
                free(dec);
            }
            int require_content_hash =
                !(hdr.global_flags & ZUPT_FLAG_DISK_IMAGE) ||
                (hdr.global_flags & ZUPT_FLAG_DISK_CONTENT_HASH);
            if (fok && (tested_size != e->uncompressed_size ||
                        (require_content_hash &&
                         tested_hash != e->content_hash))) {
                err = ZUPT_ERR_BAD_CHECKSUM;
                fok = 0;
            }
            if (fok) { if (zupt_internal_verbose(opts)) fprintf(stderr, "  OK: %s\n", e->path); pass++; }
            else { fprintf(stderr, "  FAIL: %s (%s)\n", e->path, zupt_strerror(err)); fail++; }
        }
        zupt_legacy_disk_aad_map_free(&legacy_aad_map);
    }

    printf("\n  Test: %d passed, %d failed (%d files)\n", pass, fail, n);
    free(ents);
    return fail>0 ? ZUPT_ERR_BAD_CHECKSUM : ZUPT_OK;
}

zupt_error_t zupt_test_archive(const char *arc, zupt_options_t *opts) {
    FILE *f = zupt_fopen_path(arc, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open '%s'\n", arc);
        return ZUPT_ERR_IO;
    }
    zupt_error_t result = zupt_test_archive_stream(f, opts);
    if (fclose(f) != 0 && result == ZUPT_OK) result = ZUPT_ERR_IO;
    return result;
}

/* ═══════════════════════════════════════════════════════════════════
 * ARCHIVE INFO — read-only metadata inspection (no password needed)
 *
 * Shows: format version, creation time, UUID, flags (encrypted,
 * solid, multithreaded, PQ, dedup, disk), archive size, block count.
 * Does NOT decrypt or verify checksums — works on any archive.
 * ═══════════════════════════════════════════════════════════════════ */
zupt_error_t zupt_archive_info(const char *path) {
    FILE *f = zupt_fopen_path(path, "rb");
    if (!f) { fprintf(stderr, "Error: Cannot open '%s': %s\n", path, strerror(errno)); return ZUPT_ERR_IO; }

    zupt_archive_header_t hdr;
    uint8_t serialized_header[ZUPT_ARCHIVE_HEADER_SIZE];
    if (fread(serialized_header, 1, sizeof(serialized_header), f) !=
        sizeof(serialized_header)) {
        fprintf(stderr, "Error: Not a .zupt archive (file too small)\n");
        fclose(f); return ZUPT_ERR_CORRUPT;
    }
    deserialize_archive_header(serialized_header, &hdr);
    if (hdr.magic[0]!=ZUPT_MAGIC_0 || hdr.magic[1]!=ZUPT_MAGIC_1 ||
        hdr.magic[2]!=ZUPT_MAGIC_2 || hdr.magic[3]!=ZUPT_MAGIC_3) {
        fprintf(stderr, "Error: Not a .zupt archive (bad magic)\n");
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
    if (file_size >= ZUPT_FOOTER_SIZE + ZUPT_AIT_SIZE) {
        fseeko(f, -(int64_t)(ZUPT_FOOTER_SIZE + ZUPT_AIT_SIZE), SEEK_END);
        zupt_footer_t ft;
        uint8_t serialized_footer[ZUPT_FOOTER_SIZE];
        if (fread(serialized_footer, 1, sizeof(serialized_footer), f) ==
            sizeof(serialized_footer)) {
            deserialize_footer(serialized_footer, &ft);
            if (ft.footer_magic[0]=='Z' && ft.footer_magic[1]=='E' &&
                ft.footer_magic[2]=='N' && ft.footer_magic[3]=='D') {
                total_blocks = ft.total_blocks;
                has_footer = 1;
                has_ait = 1;
            }
        }
    }
    if (!has_footer && file_size > ZUPT_FOOTER_SIZE) {
        fseeko(f, -(int64_t)ZUPT_FOOTER_SIZE, SEEK_END);
        zupt_footer_t ft;
        uint8_t serialized_footer[ZUPT_FOOTER_SIZE];
        if (fread(serialized_footer, 1, sizeof(serialized_footer), f) ==
            sizeof(serialized_footer)) {
            deserialize_footer(serialized_footer, &ft);
            if (ft.footer_magic[0]=='Z' && ft.footer_magic[1]=='E' &&
                ft.footer_magic[2]=='N' && ft.footer_magic[3]=='D') {
                total_blocks = ft.total_blocks;
                has_footer = 1;
            }
        }
    }

    /* Read the real enc_type from the encryption-header block so `info` can
     * distinguish hybrid --pq (0x02) from full --pq-only (0x06), the SDK-v2
     * (0x03) and sealed-box (0x05) modes — the ZUPT_FLAG_PQ_HYBRID header flag
     * is a generic PQ indicator set by all of them. Block layout from
     * write_enc_header: 7-byte prefix (magic0,magic1,block_type,codec u16,
     * flags u16) + varint(len) + varint(len) + u64 xxh64 + enc_hdr[0]=enc_type. */
    uint8_t enc_type = 0;
    /* encryption_header_off is attacker-controlled; bound it inside the file
     * before the (off_t)+7 arithmetic so the signed addition cannot overflow
     * (UB) and the seek stays in-range. All subsequent reads are EOF-checked. */
    if ((hdr.global_flags & ZUPT_FLAG_ENCRYPTED) && hdr.encryption_header_off != 0 &&
        hdr.encryption_header_off < file_size && (file_size - hdr.encryption_header_off) > 7 &&
        fseeko(f, (off_t)hdr.encryption_header_off + 7, SEEK_SET) == 0) {
        uint64_t l1 = 0, l2 = 0;
        if (zupt_read_varint(f, &l1) > 0 && zupt_read_varint(f, &l2) > 0 &&
            fseeko(f, 8, SEEK_CUR) == 0) {
            uint8_t b;
            if (fread(&b, 1, 1, f) == 1) enc_type = b;
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
    if (fl & ZUPT_FLAG_PQ_HYBRID) {
        switch (enc_type) {
            case ZUPT_ENC_PQ_ONLY:
                printf("  Post-quantum:  YES (ML-KEM-768 only, no classical layer)\n");
                break;
            case ZUPT_ENC_PQ_SDK_V2:
                printf("  Post-quantum:  YES (ML-KEM-768 + X25519, SDK v2 + HPKE)\n");
                break;
            case ZUPT_ENC_PQ_BOX_V1:
                printf("  Post-quantum:  YES (ML-KEM-768 + X25519, sealed box)\n");
                break;
            case ZUPT_ENC_PQ_HYBRID:
            default:
                printf("  Post-quantum:  YES (ML-KEM-768 + X25519, hybrid)\n");
                break;
        }
    }
    if (fl & ZUPT_FLAG_SOLID)
        printf("  Solid:         YES\n");
    if (fl & ZUPT_FLAG_MULTITHREADED)
        printf("  Multithreaded: YES\n");
    if (fl & ZUPT_FLAG_DEDUP)
        printf("  Dedup:         YES (block-level)\n");
    if (fl & ZUPT_FLAG_DISK_IMAGE)
        printf("  Disk image:    YES\n");
    if (hdr.comment_offset != 0)
        printf("  Comment:       present (use 'zupt extract' with the right key to read)\n");
    printf("  Flags:         0x%04X\n", fl);
    printf("\n");

    return ZUPT_OK;
}
