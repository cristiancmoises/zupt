/*
 * Zupt v2.1.4 — Full-Disk Backup/Restore
 * Copyright (c) 2026 Cristian Cezar Moisés — MIT License
 *
 * Reads a raw block device or file, compresses in streaming chunks,
 * writes a single-file solid .zupt archive. Detects all-zero blocks
 * (sparse regions) and stores them as STORE codec with minimal overhead.
 *
 * Design:
 *   - Streaming: reads source in block_size chunks (default 4MB for disks)
 *   - Sparse detection: zero blocks stored as ZUPT_CODEC_STORE (1 byte overhead)
 *   - Multi-threaded: uses existing zpar_ctx_t parallel pipeline
 *   - Encryption: full support for password (-p) and PQ (--pq) modes
 *   - Progress: real-time progress bar on stderr
 *   - Portable: works on Linux, macOS, *BSD (raw /dev/ access)
 *     On Android/Termux: requires root for block devices
 *
 * Archive format: standard .zupt with ZUPT_FLAG_DISK_IMAGE set.
 *   - Single index entry with path = source device/file path
 *   - Content = raw byte-for-byte disk image (decompressed)
 *   - Sparse blocks encoded as codec=STORE with all-zero payload
 *
 * Usage:
 *   zupt disk backup output.zupt /dev/sda1
 *   zupt disk backup -p secret output.zupt /dev/nvme0n1p2
 *   zupt disk backup --pq pub.key output.zupt disk.img
 *   zupt disk restore archive.zupt /dev/sda1
 *   zupt disk restore -p secret archive.zupt /dev/sda1
 */
#define _GNU_SOURCE
#include "zupt.h"
#include "zupt_cpuid.h"
#include "vaptvupt_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
  #include <io.h>
  #define fseeko _fseeki64
  #define ftello _ftelli64
#else
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
  #ifdef __linux__
    #include <sys/ioctl.h>
    #include <linux/fs.h>  /* BLKGETSIZE64 */
  #endif
  #ifdef __APPLE__
    #include <sys/disk.h>  /* DKIOCGETBLOCKCOUNT, DKIOCGETBLOCKSIZE */
  #endif
#endif

/* ═══════════════════════════════════════════════════════════════════
 * DEVICE SIZE DETECTION
 * ═══════════════════════════════════════════════════════════════════ */

static int64_t get_device_size(const char *path) {
#ifdef _WIN32
    /* Windows: use GetFileSizeEx for files, IOCTL_DISK_GET_LENGTH_INFO for devices */
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER sz;
    if (GetFileSizeEx(h, &sz)) { CloseHandle(h); return (int64_t)sz.QuadPart; }
    /* Try disk IOCTL */
    GET_LENGTH_INFORMATION gli;
    DWORD ret;
    if (DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &gli, sizeof(gli), &ret, NULL)) {
        CloseHandle(h); return (int64_t)gli.Length.QuadPart;
    }
    CloseHandle(h);
    return -1;
#else
    /* Open first, then fstat on the fd — eliminates TOCTOU race between
     * stat() and open() where the path could change between the two calls. */
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }

    if (S_ISREG(st.st_mode)) {
        int64_t sz = (int64_t)st.st_size;
        close(fd);
        return sz;
    }

  #ifdef __linux__
    if (S_ISBLK(st.st_mode)) {
        uint64_t sz = 0;
        if (ioctl(fd, BLKGETSIZE64, &sz) == 0) {
            close(fd);
            return (int64_t)sz;
        }
        close(fd);
        return -1;
    }
  #endif

  #ifdef __APPLE__
    if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
        uint64_t bc = 0, bs = 0;
        if (ioctl(fd, DKIOCGETBLOCKCOUNT, &bc) == 0 &&
            ioctl(fd, DKIOCGETBLOCKSIZE, &bs) == 0) {
            close(fd);
            return (int64_t)(bc * bs);
        }
        close(fd);
        return -1;
    }
  #endif

    /* FreeBSD/generic: try seeking to end */
    off_t end = lseek(fd, 0, SEEK_END);
    close(fd);
    return (end >= 0) ? (int64_t)end : -1;
#endif
}

/* ═══════════════════════════════════════════════════════════════════
 * SPARSE DETECTION
 * ═══════════════════════════════════════════════════════════════════ */

/* Check if a block is all zeros. Uses 8-byte wide check for speed. */
static int block_is_zero(const uint8_t *buf, size_t len) {
    /* Check 8 bytes at a time */
    const uint64_t *p64 = (const uint64_t *)(const void *)buf;
    size_t n64 = len / 8;
    for (size_t i = 0; i < n64; i++) {
        if (p64[i] != 0) return 0;
    }
    /* Check remaining bytes */
    for (size_t i = n64 * 8; i < len; i++) {
        if (buf[i] != 0) return 0;
    }
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════
 * PROGRESS BAR
 * ═══════════════════════════════════════════════════════════════════ */

static void disk_progress(const char *label, uint64_t done, uint64_t total, time_t start) {
    if (total == 0) return;
    int pct = (int)(done * 100 / total);
    int bar = pct / 2;
    char buf[60]; memset(buf, ' ', 50); buf[50] = '\0';
    for (int i = 0; i < bar && i < 50; i++) buf[i] = '#';

    time_t elapsed = time(NULL) - start;
    if (elapsed < 1) elapsed = 1;
    double speed = (double)done / (double)elapsed / 1048576.0;

    char done_str[16], total_str[16];
    zupt_format_size(done, done_str, sizeof(done_str));
    zupt_format_size(total, total_str, sizeof(total_str));

    fprintf(stderr, "\r  %s [%-50s] %3d%%  %s / %s  %.1f MB/s",
            label, buf, pct, done_str, total_str, speed);
    if (done >= total) fprintf(stderr, "\n");
    fflush(stderr);
}

/* ═══════════════════════════════════════════════════════════════════
 * DISK BACKUP (compress device → archive)
 * ═══════════════════════════════════════════════════════════════════ */

/* Forward declarations from zupt_format.c */
extern int zupt_write_varint(FILE *f, uint64_t v);

zupt_error_t zupt_disk_backup(const char *output_path, const char *source_path,
                               zupt_options_t *opts) {
    /* Detect source size */
    int64_t source_size = get_device_size(source_path);
    if (source_size <= 0) {
        fprintf(stderr, "Error: Cannot determine size of '%s': %s\n",
                source_path, strerror(errno));
        return ZUPT_ERR_IO;
    }

    /* Use 4MB blocks for disk images (good balance of ratio vs memory) */
    if (opts->block_size == 0)
        opts->block_size = 4 * 1024 * 1024;
    if (opts->block_size < ZUPT_MIN_BLOCK_SZ)
        opts->block_size = ZUPT_MIN_BLOCK_SZ;

    /* Resolve AUTO codec */
    if (opts->codec_id == ZUPT_CODEC_AUTO)
        opts->codec_id = zupt_resolve_auto_codec();

    char sz_str[16];
    zupt_format_size((uint64_t)source_size, sz_str, sizeof(sz_str));
    fprintf(stderr, "  Source:       %s (%s)\n", source_path, sz_str);
    fprintf(stderr, "  Block size:   %u bytes\n", opts->block_size);
    fprintf(stderr, "  Codec:        %s\n", zupt_codec_name(opts->codec_id));
    if (opts->encrypt) fprintf(stderr, "  Encryption:   ENABLED\n");
    fprintf(stderr, "\n");

    /* Open source */
    FILE *src_f = fopen(source_path, "rb");
    if (!src_f) {
        fprintf(stderr, "Error: Cannot open '%s': %s\n", source_path, strerror(errno));
        return ZUPT_ERR_IO;
    }

    /* Open output */
    FILE *out = fopen(output_path, "wb");
    if (!out) {
        fprintf(stderr, "Error: Cannot create '%s': %s\n", output_path, strerror(errno));
        fclose(src_f);
        return ZUPT_ERR_IO;
    }

    int write_err = 0;

    /* ─── Write archive header ─── */
    zupt_archive_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic[0] = ZUPT_MAGIC_0; hdr.magic[1] = ZUPT_MAGIC_1;
    hdr.magic[2] = ZUPT_MAGIC_2; hdr.magic[3] = ZUPT_MAGIC_3;
    hdr.magic[4] = ZUPT_MAGIC_4; hdr.magic[5] = ZUPT_MAGIC_5;
    hdr.version_major = ZUPT_FORMAT_MAJOR;
    hdr.version_minor = ZUPT_FORMAT_MINOR;
    hdr.global_flags = ZUPT_FLAG_CKSUM_XXH64 | ZUPT_FLAG_DISK_IMAGE;
    if (opts->encrypt) hdr.global_flags |= ZUPT_FLAG_ENCRYPTED;
    if (opts->threads > 1) hdr.global_flags |= ZUPT_FLAG_MULTITHREADED;
    hdr.creation_time = (uint64_t)time(NULL) * 1000000000ULL;
    zupt_random_bytes(hdr.archive_id, 16);
    hdr.archive_id[6] = (hdr.archive_id[6] & 0x0F) | 0x40;
    hdr.archive_id[8] = (hdr.archive_id[8] & 0x3F) | 0x80;
    if (fwrite(&hdr, sizeof(hdr), 1, out) != 1) write_err = 1;

    /* ─── Encryption header ─── */
    /* ─── Encryption header (uses same code as zupt compress) ─── */
    if (opts->encrypt) {
        zupt_error_t enc_err = write_enc_header(out, &hdr, opts);
        if (enc_err != ZUPT_OK) {
            fclose(src_f); fclose(out);
            return enc_err;
        }
    }

    /* ─── Compress blocks ─── */
    uint8_t *rbuf = (uint8_t *)malloc(opts->block_size);
    size_t comp_cap = vvz_compress_bound(opts->block_size) + 512;
    if (comp_cap < zupt_lzh_bound(opts->block_size) + 512)
        comp_cap = zupt_lzh_bound(opts->block_size) + 512;
    uint8_t *cbuf = (uint8_t *)malloc(comp_cap);

    if (!rbuf || !cbuf) {
        free(rbuf); free(cbuf);
        fclose(src_f); fclose(out);
        return ZUPT_ERR_NOMEM;
    }

    uint64_t total_read = 0, total_written = 0;
    uint64_t block_seq = 0;
    uint64_t sparse_blocks = 0, data_blocks = 0;
    uint64_t first_block_off = (uint64_t)ftello(out);
    time_t start_time = time(NULL);

    while (total_read < (uint64_t)source_size) {
        size_t to_read = opts->block_size;
        if (total_read + to_read > (uint64_t)source_size)
            to_read = (size_t)((uint64_t)source_size - total_read);

        size_t nread = fread(rbuf, 1, to_read, src_f);
        if (nread == 0) break;

        /* Pad partial last block with zeros */
        if (nread < to_read)
            memset(rbuf + nread, 0, to_read - nread);

        uint64_t checksum = zupt_xxh64(rbuf, nread, 0);

        /* Sparse detection: skip zero blocks */
        uint16_t codec = opts->codec_id;
        size_t comp_size = 0;

        if (block_is_zero(rbuf, nread)) {
            codec = ZUPT_CODEC_STORE;
            comp_size = nread;
            sparse_blocks++;
        } else {
            /* Compress with selected codec */
            if (codec == ZUPT_CODEC_VAPTVUPT) {
                int64_t csz = vvz_compress(rbuf, nread, cbuf, comp_cap, opts->level);
                if (csz > 0 && (size_t)csz < nread)
                    comp_size = (size_t)csz;
            } else if (codec == ZUPT_CODEC_ZUPT_LZHP) {
                /* LZHP with prediction — must encode through prediction
                 * table before compressing, matching zupt_format.c */
                float benefit = zupt_predict_benefit(rbuf, nread);
                if (benefit > 0.02f && nread > 256) {
                    uint8_t pred[256];
                    zupt_predict_build(rbuf, nread, pred);
                    uint8_t *transformed = (uint8_t *)malloc(nread);
                    if (transformed) {
                        zupt_predict_encode(rbuf, transformed, nread, pred);
                        size_t plain = zupt_lzh_compress(transformed, nread,
                                                          cbuf + 257,
                                                          comp_cap - 257, opts->level);
                        free(transformed);
                        if (plain > 0 && 257 + plain < nread) {
                            cbuf[0] = 0x01;
                            memcpy(cbuf + 1, pred, 256);
                            comp_size = 257 + plain;
                        } else {
                            /* Prediction didn't help — fall back to plain LZH */
                            cbuf[0] = 0x00;
                            plain = zupt_lzh_compress(rbuf, nread, cbuf + 1,
                                                        comp_cap - 1, opts->level);
                            if (plain > 0 && 1 + plain < nread)
                                comp_size = 1 + plain;
                        }
                    }
                } else {
                    cbuf[0] = 0x00;
                    size_t plain = zupt_lzh_compress(rbuf, nread, cbuf + 1,
                                                      comp_cap - 1, opts->level);
                    if (plain > 0 && 1 + plain < nread)
                        comp_size = 1 + plain;
                }
            } else if (codec == ZUPT_CODEC_ZUPT_LZH) {
                comp_size = zupt_lzh_compress(rbuf, nread, cbuf, comp_cap, opts->level);
            } else if (codec == ZUPT_CODEC_ZUPT_LZ) {
                comp_size = zupt_lz_compress(rbuf, nread, cbuf, comp_cap, opts->level);
            }

            data_blocks++;
        }

        /* Fallback to store if compression didn't help */
        const uint8_t *payload;
        uint64_t payload_size;
        if (comp_size == 0 || comp_size >= nread) {
            codec = ZUPT_CODEC_STORE;
            payload = rbuf;
            payload_size = nread;
        } else {
            payload = cbuf;
            payload_size = comp_size;
        }

        /* Encrypt if active */
        uint8_t *enc_payload = NULL;
        uint16_t bflags = 0;
        if (opts->encrypt && opts->keyring.active) {
            size_t enc_len;
            enc_payload = zupt_encrypt_buffer(&opts->keyring, payload, payload_size,
                                               block_seq, &enc_len);
            if (!enc_payload) {
                free(rbuf); free(cbuf);
                fclose(src_f); fclose(out);
                return ZUPT_ERR_NOMEM;
            }
            payload = enc_payload;
            payload_size = enc_len;
            bflags |= ZUPT_BFLAG_ENCRYPTED;
        }

        /* Write block: magic + type + codec + flags + uncomp_size + comp_size + checksum + payload */
        uint8_t bm[2] = {ZUPT_BLOCK_MAGIC_0, ZUPT_BLOCK_MAGIC_1};
        fwrite(bm, 1, 2, out);
        uint8_t bt = ZUPT_BLOCK_DATA;
        fwrite(&bt, 1, 1, out);
        /* codec (2B LE) */
        uint8_t c16[2]; c16[0] = (uint8_t)(codec & 0xFF); c16[1] = (uint8_t)(codec >> 8);
        fwrite(c16, 1, 2, out);
        /* flags (2B LE) */
        uint8_t f16[2]; f16[0] = (uint8_t)(bflags & 0xFF); f16[1] = (uint8_t)(bflags >> 8);
        fwrite(f16, 1, 2, out);
        zupt_write_varint(out, (uint64_t)nread);
        zupt_write_varint(out, payload_size);
        /* checksum (8B LE) */
        uint8_t ck8[8]; for (int i = 0; i < 8; i++) ck8[i] = (uint8_t)(checksum >> (i*8));
        fwrite(ck8, 1, 8, out);
        if (fwrite(payload, 1, (size_t)payload_size, out) != (size_t)payload_size)
            write_err = 1;

        free(enc_payload);
        total_read += nread;
        total_written += payload_size;
        block_seq++;

        /* Progress */
        if (!opts->quiet)
            disk_progress("Backup", total_read, (uint64_t)source_size, start_time);
    }

    /* ─── Write index (single entry for the disk image) ─── */
    uint8_t idx_buf[4096];
    size_t idx_pos = 0;

    /* File count (4B LE) */
    idx_buf[idx_pos++] = 1; idx_buf[idx_pos++] = 0;
    idx_buf[idx_pos++] = 0; idx_buf[idx_pos++] = 0;

    /* Path (varint length + bytes) */
    size_t path_len = strlen(source_path);
    if (path_len > ZUPT_MAX_PATH - 1) path_len = ZUPT_MAX_PATH - 1;
    idx_pos += zupt_encode_varint(idx_buf + idx_pos, path_len);
    memcpy(idx_buf + idx_pos, source_path, path_len);
    idx_pos += path_len;

    /* Uncompressed size (8B LE) */
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)((uint64_t)source_size >> (i*8));
    /* Compressed size (8B LE) */
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)(total_written >> (i*8));
    /* Modification time (8B LE) */
    uint64_t mtime = (uint64_t)time(NULL) * 1000000000ULL;
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)(mtime >> (i*8));
    /* Content hash (8B LE) */
    uint64_t content_hash = zupt_xxh64(source_path, path_len, (uint64_t)source_size);
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)(content_hash >> (i*8));
    /* First block offset (8B LE) */
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)(first_block_off >> (i*8));
    /* Block count (4B LE) */
    for (int i = 0; i < 4; i++) idx_buf[idx_pos++] = (uint8_t)(block_seq >> (i*8));
    /* Attributes (4B LE) */
    idx_buf[idx_pos++] = 0; idx_buf[idx_pos++] = 0;
    idx_buf[idx_pos++] = 0; idx_buf[idx_pos++] = 0;

    /* Write index block */
    uint64_t index_offset = (uint64_t)ftello(out);
    uint64_t idx_ck = zupt_xxh64(idx_buf, idx_pos, 0);
    {
        uint8_t bm[2] = {ZUPT_BLOCK_MAGIC_0, ZUPT_BLOCK_MAGIC_1};
        fwrite(bm, 1, 2, out);
        uint8_t bt = ZUPT_BLOCK_INDEX;
        fwrite(&bt, 1, 1, out);
        uint8_t c16[2] = {0, 0}; fwrite(c16, 1, 2, out);
        uint8_t f16[2] = {0, 0}; fwrite(f16, 1, 2, out);
        zupt_write_varint(out, idx_pos);
        zupt_write_varint(out, idx_pos);
        uint8_t ck8[8]; for (int i = 0; i < 8; i++) ck8[i] = (uint8_t)(idx_ck >> (i*8));
        fwrite(ck8, 1, 8, out);
        fwrite(idx_buf, 1, idx_pos, out);
    }

    /* ─── Write footer ─── */
    zupt_footer_t ft;
    ft.index_offset = index_offset;
    ft.total_blocks = block_seq;
    ft.archive_checksum = zupt_xxh64(&hdr, sizeof(hdr), block_seq);
    ft.footer_magic[0] = 'Z'; ft.footer_magic[1] = 'E';
    ft.footer_magic[2] = 'N'; ft.footer_magic[3] = 'D';
    ft.footer_version = 1;
    fwrite(&ft, sizeof(ft), 1, out);

    /* Get final archive size before closing */
    uint64_t out_bytes = (uint64_t)ftello(out);

    free(rbuf); free(cbuf);
    fclose(src_f); fclose(out);

    /* Summary */
    time_t elapsed = time(NULL) - start_time;
    if (elapsed < 1) elapsed = 1;
    char out_sz[16], in_sz[16];

    zupt_format_size((uint64_t)source_size, in_sz, sizeof(in_sz));

    /* Re-open to get actual file size */
    {
        FILE *check = fopen(output_path, "rb");
        if (check) {
            fseeko(check, 0, SEEK_END);
            out_bytes = (uint64_t)ftello(check);
            fclose(check);
        }
    }
    zupt_format_size(out_bytes, out_sz, sizeof(out_sz));

    fprintf(stderr, "\n  Disk backup complete:\n");
    fprintf(stderr, "  Source:       %s\n", in_sz);
    fprintf(stderr, "  Archive:      %s\n", out_sz);
    fprintf(stderr, "  Ratio:        %.2f:1\n",
            out_bytes > 0 ? (double)source_size / (double)out_bytes : 1.0);
    fprintf(stderr, "  Blocks:       %llu (%llu data, %llu sparse/zero)\n",
            (unsigned long long)block_seq,
            (unsigned long long)data_blocks,
            (unsigned long long)sparse_blocks);
    fprintf(stderr, "  Speed:        %.1f MB/s\n",
            (double)source_size / (double)elapsed / 1048576.0);
    if (opts->encrypt) fprintf(stderr, "  Encrypted:    YES\n");
    fprintf(stderr, "\n");

    return write_err ? ZUPT_ERR_IO : ZUPT_OK;
}

/* ═══════════════════════════════════════════════════════════════════
 * DISK RESTORE (extract archive → device/file)
 *
 * Rewritten for v2.1.3: uses the same read_block() / read_enc_header() /
 * decompress_block() functions as zupt_extract_archive(). This eliminates
 * the hand-rolled block parser that caused checksum mismatches due to
 * encryption header format differences (52-byte vs 53-byte) and seek
 * offset errors.
 *
 * Flow:
 *   1. Read archive header → validate magic + DISK_IMAGE flag
 *   2. Read encryption header (if encrypted) → derive keys using
 *      read_enc_header() which handles PQ, PBKDF2, and legacy formats
 *   3. Read data blocks sequentially with read_block()
 *   4. Decompress+decrypt+checksum each block with decompress_block()
 *   5. Write decompressed data to target
 * ═══════════════════════════════════════════════════════════════════ */

zupt_error_t zupt_disk_restore(const char *archive_path, const char *target_path,
                                zupt_options_t *opts) {
    FILE *f = fopen(archive_path, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open '%s': %s\n", archive_path, strerror(errno));
        return ZUPT_ERR_IO;
    }

    /* ─── Read archive header ─── */
    zupt_archive_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
        fclose(f);
        fprintf(stderr, "Error: Cannot read archive header\n");
        return ZUPT_ERR_IO;
    }

    if (hdr.magic[0] != ZUPT_MAGIC_0 || hdr.magic[1] != ZUPT_MAGIC_1 ||
        hdr.magic[2] != ZUPT_MAGIC_2 || hdr.magic[3] != ZUPT_MAGIC_3) {
        fclose(f);
        fprintf(stderr, "Error: Not a .zupt archive\n");
        return ZUPT_ERR_BAD_MAGIC;
    }

    if (!(hdr.global_flags & ZUPT_FLAG_DISK_IMAGE)) {
        fclose(f);
        fprintf(stderr, "Error: Archive is not a disk image. Use 'zupt extract' instead.\n");
        return ZUPT_ERR_INVALID;
    }

    /* ─── Read encryption header (uses same code as zupt extract) ─── */
    if (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) {
        if (!opts->encrypt && opts->password[0] == '\0' && !opts->pq_mode) {
            fclose(f);
            fprintf(stderr, "Error: Archive is encrypted. Use -p or --pq to provide key.\n");
            return ZUPT_ERR_AUTH_FAIL;
        }
        opts->encrypt = 1;

        zupt_error_t enc_err = read_enc_header(f, &hdr, opts);
        if (enc_err != ZUPT_OK) {
            fclose(f);
            fprintf(stderr, "Error: Encryption header read failed (%s)\n",
                    zupt_strerror(enc_err));
            return enc_err;
        }
    }

    /* ─── Read footer to get total block count ─── */
    int64_t after_enc_pos = ftello(f);  /* Save position after enc header */

    fseeko(f, -(int64_t)sizeof(zupt_footer_t), SEEK_END);
    zupt_footer_t ft;
    if (fread(&ft, sizeof(ft), 1, f) != 1) {
        fclose(f);
        return ZUPT_ERR_CORRUPT;
    }
    if (ft.footer_magic[0] != 'Z' || ft.footer_magic[1] != 'E' ||
        ft.footer_magic[2] != 'N' || ft.footer_magic[3] != 'D') {
        fclose(f);
        fprintf(stderr, "Error: Invalid footer magic\n");
        return ZUPT_ERR_BAD_MAGIC;
    }

    /* ─── Seek back to first data block ─── */
    fseeko(f, after_enc_pos, SEEK_SET);

    /* ─── Open target for writing ───
     * Block devices require raw POSIX I/O (open/write) because stdio
     * buffering can cause misaligned or partial writes that corrupt data.
     * O_SYNC ensures each write is flushed to the device before returning.
     * For loop devices, this ensures data reaches the backing file.
     *
     * To avoid TOCTOU races (stat then open on a path that could change),
     * we open the fd first, then fstat on the fd to classify it. */
#ifdef _WIN32
    FILE *tgt = fopen(target_path, "wb");
    if (!tgt) {
        fprintf(stderr, "Error: Cannot open target '%s': %s\n",
                target_path, strerror(errno));
        fclose(f);
        return ZUPT_ERR_IO;
    }
#else
    int tgt_fd;
    int is_block_dev = 0;

    /* Open the target — try without O_CREAT first (for existing devices/files),
     * fall back to O_CREAT | O_TRUNC for new files. */
    tgt_fd = open(target_path, O_WRONLY);
    if (tgt_fd < 0) {
        tgt_fd = open(target_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }
    if (tgt_fd < 0) {
        fprintf(stderr, "Error: Cannot open target '%s': %s\n",
                target_path, strerror(errno));
        fclose(f);
        return ZUPT_ERR_IO;
    }

    /* Classify the fd (not the path) to avoid TOCTOU */
    {
        struct stat tgt_st;
        if (fstat(tgt_fd, &tgt_st) == 0 &&
            (S_ISBLK(tgt_st.st_mode) || S_ISCHR(tgt_st.st_mode))) {
            is_block_dev = 1;
            /* Enable synchronous I/O for block devices */
            int fl = fcntl(tgt_fd, F_GETFL);
            if (fl >= 0) fcntl(tgt_fd, F_SETFL, fl | O_SYNC);
        } else if (fstat(tgt_fd, &tgt_st) == 0 && S_ISREG(tgt_st.st_mode)) {
            /* Regular file — truncate if we opened without O_TRUNC */
            if (ftruncate(tgt_fd, 0) != 0) {
                /* Non-fatal: file may already be empty */
            }
        }
    }
#endif

    fprintf(stderr, "  Restoring disk image to: %s\n", target_path);
    fprintf(stderr, "  Blocks: %llu\n\n", (unsigned long long)ft.total_blocks);

    time_t start_time = time(NULL);
    uint64_t total_written = 0;
    uint64_t block_seq = 0;
    int errors = 0;

    /* ─── Read and restore blocks sequentially ─── */
    for (uint64_t bi = 0; bi < ft.total_blocks; bi++) {
        zupt_block_t blk;
        zupt_error_t rerr = read_block(f, &blk);

        if (rerr != ZUPT_OK) {
            fprintf(stderr, "  Block %llu: read error (%s)\n",
                    (unsigned long long)bi, zupt_strerror(rerr));
            errors++;
            break;
        }

        /* Skip non-data blocks (index, etc.) */
        if (blk.block_type == ZUPT_BLOCK_INDEX) {
            free(blk.payload);
            break;  /* Reached index — all data blocks done */
        }
        if (blk.block_type != ZUPT_BLOCK_DATA) {
            free(blk.payload);
            continue;  /* Skip unknown block types */
        }

        /* Decompress + decrypt + verify checksum */
        uint8_t *out_buf = NULL;
        size_t out_len = 0;
        zupt_error_t derr = decompress_block(&blk, &opts->keyring,
                                              block_seq, &out_buf, &out_len);
        free(blk.payload);

        if (derr != ZUPT_OK) {
            fprintf(stderr, "  Block %llu: decompression/checksum failed (%s)\n",
                    (unsigned long long)bi, zupt_strerror(derr));
            errors++;
            break;
        }

        /* Write to target */
        int write_ok = 0;
#ifdef _WIN32
        write_ok = (fwrite(out_buf, 1, out_len, tgt) == out_len);
#else
        {
            size_t written = 0;
            while (written < out_len) {
                ssize_t w = write(tgt_fd, out_buf + written, out_len - written);
                if (w <= 0) break;
                written += (size_t)w;
            }
            write_ok = (written == out_len);
        }
#endif
        if (!write_ok) {
            fprintf(stderr, "  Block %llu: write error (%s)\n",
                    (unsigned long long)bi, strerror(errno));
            free(out_buf);
            errors++;
            break;
        }

        total_written += out_len;
        block_seq++;
        free(out_buf);

        /* Progress */
        if (!opts->quiet && ft.total_blocks > 0)
            disk_progress("Restore", bi + 1, ft.total_blocks, start_time);
    }

    fclose(f);
#ifdef _WIN32
    fclose(tgt);
#else
    if (tgt_fd >= 0) {
        fsync(tgt_fd);   /* Flush file descriptor buffers */
        close(tgt_fd);
    }
    if (is_block_dev) {
        sync();  /* Force kernel to flush ALL dirty pages to disk.
                  * Critical for loop devices: fsync on the loop fd
                  * may not flush the backing file's page cache. */
    }
#endif

    if (errors > 0) {
        fprintf(stderr, "\n  Restore FAILED: %d error(s)\n", errors);
        return ZUPT_ERR_CORRUPT;
    }

    char sz_str[16];
    zupt_format_size(total_written, sz_str, sizeof(sz_str));
    time_t elapsed = time(NULL) - start_time;
    if (elapsed < 1) elapsed = 1;
    fprintf(stderr, "\n  Restore complete: %s written (%.1f MB/s)\n\n",
            sz_str, (double)total_written / (double)elapsed / 1048576.0);

    return ZUPT_OK;
}
