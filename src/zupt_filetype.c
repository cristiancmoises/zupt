/*
 * Zupt v2.0.0 — Adaptive Compression: File Type Detection
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Detects file type by magic bytes (not just extension) and returns
 * a recommended compression level. Already-compressed files (JPEG,
 * PNG, ZIP, etc.) get STORE to avoid wasting CPU on incompressible data.
 *
 * Returns: -1 = store (incompressible), 0 = use default, 5 = medium, 9 = max
 */
#include "zupt.h"
#include <string.h>

/* Magic byte signatures for common compressed/media formats */
typedef struct {
    const uint8_t *magic;
    size_t         magic_len;
    int            level_hint;  /* -1=store, 0=default, 5=medium, 9=max */
} zupt_magic_entry_t;

static const uint8_t M_JPEG[]  = {0xFF, 0xD8, 0xFF};
static const uint8_t M_PNG[]   = {0x89, 0x50, 0x4E, 0x47};
static const uint8_t M_GIF[]   = {0x47, 0x49, 0x46, 0x38};
static const uint8_t M_ZIP[]   = {0x50, 0x4B, 0x03, 0x04};
static const uint8_t M_GZIP[]  = {0x1F, 0x8B};
static const uint8_t M_ZSTD[]  = {0x28, 0xB5, 0x2F, 0xFD};
static const uint8_t M_XZ[]    = {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};
static const uint8_t M_7Z[]    = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
static const uint8_t M_BZ2[]   = {0x42, 0x5A, 0x68};
static const uint8_t M_LZ4[]   = {0x04, 0x22, 0x4D, 0x18};
static const uint8_t M_MP4_1[] = {0x00, 0x00, 0x00};  /* MP4/MOV (check byte 4 for 'ftyp') */
static const uint8_t M_WEBP[]  = {0x52, 0x49, 0x46, 0x46}; /* RIFF (check for WEBP at offset 8) */
static const uint8_t M_FLAC[]  = {0x66, 0x4C, 0x61, 0x43};
static const uint8_t M_OGG[]   = {0x4F, 0x67, 0x67, 0x53};
static const uint8_t M_PDF[]   = {0x25, 0x50, 0x44, 0x46}; /* %PDF */
static const uint8_t M_ELF[]   = {0x7F, 0x45, 0x4C, 0x46}; /* ELF binary */

static const zupt_magic_entry_t MAGIC_TABLE[] = {
    /* Already compressed — store, don't waste CPU */
    {M_JPEG,  3, -1},
    {M_PNG,   4, -1},
    {M_GIF,   4, -1},
    {M_ZIP,   4, -1},
    {M_GZIP,  2, -1},
    {M_ZSTD,  4, -1},
    {M_XZ,    6, -1},
    {M_7Z,    6, -1},
    {M_BZ2,   3, -1},
    {M_LZ4,   4, -1},
    {M_FLAC,  4, -1},
    {M_OGG,   4, -1},
    /* Partially compressed — medium effort */
    {M_PDF,   4,  5},
    {M_ELF,   4,  5},
    /* Sentinel */
    {NULL, 0, 0}
};

int zupt_detect_filetype(const uint8_t *header, size_t header_len) {
    if (header_len < 6) return 0; /* Too small to identify — use default */

    /* Check magic byte table */
    for (int i = 0; MAGIC_TABLE[i].magic != NULL; i++) {
        if (header_len >= MAGIC_TABLE[i].magic_len &&
            memcmp(header, MAGIC_TABLE[i].magic, MAGIC_TABLE[i].magic_len) == 0) {

            /* Special case: MP4/MOV needs 'ftyp' at offset 4 */
            if (MAGIC_TABLE[i].magic == M_MP4_1 && header_len >= 8) {
                if (memcmp(header + 4, "ftyp", 4) == 0) return -1;
                continue; /* Not MP4, keep checking */
            }
            /* Special case: RIFF → check for WEBP */
            if (MAGIC_TABLE[i].magic == M_WEBP && header_len >= 12) {
                if (memcmp(header + 8, "WEBP", 4) == 0) return -1;
                /* Could be WAV/AVI — use default */
                continue;
            }
            return MAGIC_TABLE[i].level_hint;
        }
    }

    /* Heuristic: check if data looks like text (high ASCII ratio) */
    int text_chars = 0;
    size_t check_len = header_len > 512 ? 512 : header_len;
    for (size_t i = 0; i < check_len; i++) {
        uint8_t c = header[i];
        if ((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t')
            text_chars++;
    }
    if (check_len > 0 && (size_t)text_chars * 100 / check_len > 90)
        return 9; /* Highly textual — max compression */

    return 0; /* Unknown — use default level */
}
