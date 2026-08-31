/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 * ZUPT v2.1.4 — Full-Disk Backup/Restore
 * Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-or-later
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
 *   - Single index entry with a safe basename label for the source
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
#include "zupt_internal.h"
#include "zupt_cpuid.h"
#include "vaptvupt_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
  #include <fcntl.h>
  #include <io.h>
  #ifndef fseeko
    #define fseeko _fseeki64
  #endif
  #ifndef ftello
    #define ftello _ftelli64
  #endif
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
  #ifdef __FreeBSD__
    #include <sys/disk.h>  /* DIOCGMEDIASIZE */
  #endif
#endif

static int disk_label_reserved(const char *label, size_t length) {
    size_t base = 0;
    while (base < length && label[base] != '.') base++;
    char upper[5] = {0};
    if (base > 4) return 0;
    for (size_t i = 0; i < base; i++) {
        unsigned char c = (unsigned char)label[i];
        upper[i] = (char)(c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c);
    }
    if (strcmp(upper, "CON") == 0 || strcmp(upper, "PRN") == 0 ||
        strcmp(upper, "AUX") == 0 || strcmp(upper, "NUL") == 0)
        return 1;
    return base == 4 &&
           ((memcmp(upper, "COM", 3) == 0 ||
             memcmp(upper, "LPT", 3) == 0) &&
            upper[3] >= '1' && upper[3] <= '9');
}

static const char *disk_archive_label(const char *source,
                                      char label[ZUPT_MAX_PATH]) {
    const char *leaf = source ? source : "";
    for (const char *p = leaf; *p; p++)
        if (*p == '/' || *p == '\\') leaf = p + 1;
    size_t length = strlen(leaf);
    int safe = length > 0 && length < ZUPT_MAX_PATH &&
               strcmp(leaf, ".") != 0 && strcmp(leaf, "..") != 0 &&
               leaf[length - 1] != '.' && leaf[length - 1] != ' ' &&
               !disk_label_reserved(leaf, length);
    for (size_t i = 0; safe && i < length; i++) {
        unsigned char c = (unsigned char)leaf[i];
        if (c < 0x20 || c == 0x7f || c == ':') safe = 0;
    }
    if (!safe) leaf = "disk-image.raw";
    length = strlen(leaf);
    memcpy(label, leaf, length + 1);
    return label;
}

/* ═══════════════════════════════════════════════════════════════════
 * DEVICE SIZE DETECTION
 * ═══════════════════════════════════════════════════════════════════ */

/* Measure the already-open source so size discovery and subsequent reads use
 * the same kernel object.  The caller owns the stream and its file position. */
static int64_t get_device_size(FILE *stream) {
#ifdef _WIN32
    /* Windows: use the CRT stream's handle for files and raw devices. */
    intptr_t raw_handle = _get_osfhandle(_fileno(stream));
    if (raw_handle == -1) return -1;
    HANDLE h = (HANDLE)raw_handle;
    LARGE_INTEGER sz;
    if (GetFileSizeEx(h, &sz)) return (int64_t)sz.QuadPart;
    /* Try disk IOCTL */
    GET_LENGTH_INFORMATION gli;
    DWORD ret;
    if (DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &gli,
                        sizeof(gli), &ret, NULL))
        return (int64_t)gli.Length.QuadPart;
    return -1;
#else
    int fd = fileno(stream);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) return -1;

    if (S_ISREG(st.st_mode)) return (int64_t)st.st_size;

  #ifdef __linux__
    if (S_ISBLK(st.st_mode)) {
        uint64_t sz = 0;
        if (ioctl(fd, BLKGETSIZE64, &sz) == 0) return (int64_t)sz;
        return -1;
    }
  #endif

  #ifdef __APPLE__
    if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
        uint64_t bc = 0, bs = 0;
        if (ioctl(fd, DKIOCGETBLOCKCOUNT, &bc) == 0 &&
            ioctl(fd, DKIOCGETBLOCKSIZE, &bs) == 0)
            return (int64_t)(bc * bs);
        return -1;
    }
  #endif

    /* FreeBSD/generic: try seeking to end */
    off_t end = lseek(fd, 0, SEEK_END);
    if (end >= 0 && lseek(fd, 0, SEEK_SET) < 0) return -1;
    return (end >= 0) ? (int64_t)end : -1;
#endif
}

typedef struct {
#ifdef _WIN32
    DWORD volume_serial;
    DWORD file_index_high;
    DWORD file_index_low;
#else
    dev_t device;
    ino_t inode;
#endif
} disk_file_identity_t;

static int disk_stream_identity(FILE *stream, disk_file_identity_t *identity) {
    if (!stream || !identity) {
        errno = EINVAL;
        return 0;
    }
#ifdef _WIN32
    intptr_t raw_handle = _get_osfhandle(_fileno(stream));
    BY_HANDLE_FILE_INFORMATION info;
    if (raw_handle == -1 ||
        !GetFileInformationByHandle((HANDLE)raw_handle, &info)) {
        errno = EIO;
        return 0;
    }
    identity->volume_serial = info.dwVolumeSerialNumber;
    identity->file_index_high = info.nFileIndexHigh;
    identity->file_index_low = info.nFileIndexLow;
#else
    struct stat info;
    if (fstat(fileno(stream), &info) != 0) return 0;
    identity->device = info.st_dev;
    identity->inode = info.st_ino;
#endif
    return 1;
}

static int disk_identity_equal(const disk_file_identity_t *left,
                               const disk_file_identity_t *right) {
#ifdef _WIN32
    return left->volume_serial == right->volume_serial &&
           left->file_index_high == right->file_index_high &&
           left->file_index_low == right->file_index_low;
#else
    return left->device == right->device && left->inode == right->inode;
#endif
}

/* Return 1 for the same kernel object, 0 for a different/missing output, and
 * -1 when an existing output cannot be inspected safely.  Path lookup follows
 * the final symlink deliberately: an output symlink to the source itself is
 * just as destructive as spelling the source path directly. */
static int disk_source_matches_output(FILE *source, const char *output_path) {
    disk_file_identity_t source_identity;
    disk_file_identity_t output_identity;
    if (!disk_stream_identity(source, &source_identity)) return -1;
#ifdef _WIN32
    wchar_t *wide_output = zupt_win_utf8_to_wide_alloc(output_path);
    if (!wide_output) {
        errno = EINVAL;
        return -1;
    }
    HANDLE output_handle = CreateFileW(
        wide_output, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wide_output);
    if (output_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            return 0;
        errno = EACCES;
        return -1;
    }
    BY_HANDLE_FILE_INFORMATION info;
    int inspected = GetFileInformationByHandle(output_handle, &info) != 0;
    if (!CloseHandle(output_handle)) inspected = 0;
    if (!inspected) {
        errno = EIO;
        return -1;
    }
    output_identity.volume_serial = info.dwVolumeSerialNumber;
    output_identity.file_index_high = info.nFileIndexHigh;
    output_identity.file_index_low = info.nFileIndexLow;
#else
    struct stat info;
    if (stat(output_path, &info) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) return 0;
        return -1;
    }
    output_identity.device = info.st_dev;
    output_identity.inode = info.st_ino;
#endif
    return disk_identity_equal(&source_identity, &output_identity);
}

/* Disk restore cannot roll a block device back after a late validation error.
 * Copy the already-open archive into a private, automatically removed file;
 * both the complete preflight and the restore then read this stable snapshot. */
static FILE *open_private_restore_snapshot(void) {
#ifdef _WIN32
    wchar_t default_directory[MAX_PATH + 1];
    wchar_t *override_directory = NULL;
    const wchar_t *directory = NULL;
    const char *override_utf8 = getenv("ZUPT_TMPDIR");
    if (override_utf8 && override_utf8[0] != '\0') {
        override_directory = zupt_win_utf8_to_wide_alloc(override_utf8);
        directory = override_directory;
    } else {
        DWORD length = GetTempPathW(MAX_PATH + 1, default_directory);
        if (length == 0 || length > MAX_PATH) {
            errno = EIO;
            return NULL;
        }
        directory = default_directory;
    }
    if (!directory) {
        errno = EINVAL;
        return NULL;
    }

    size_t directory_length = wcslen(directory);
    size_t path_capacity = directory_length + 64;
    wchar_t *path = (wchar_t *)calloc(path_capacity, sizeof(*path));
    if (!path) {
        free(override_directory);
        errno = ENOMEM;
        return NULL;
    }

    FILE *stream = NULL;
    static const wchar_t hex[] = L"0123456789abcdef";
    for (int attempt = 0; attempt < 64 && !stream; attempt++) {
        uint8_t nonce[16];
        zupt_random_bytes(nonce, sizeof(nonce));
        size_t position = 0;
        memcpy(path, directory, directory_length * sizeof(*path));
        position = directory_length;
        if (position > 0 && path[position - 1] != L'\\' &&
            path[position - 1] != L'/')
            path[position++] = L'\\';
        const wchar_t prefix[] = L"zupt-restore-";
        memcpy(path + position, prefix, (wcslen(prefix)) * sizeof(*path));
        position += wcslen(prefix);
        for (size_t i = 0; i < sizeof(nonce); i++) {
            path[position++] = hex[nonce[i] >> 4];
            path[position++] = hex[nonce[i] & 0x0f];
        }
        const wchar_t suffix[] = L".tmp";
        memcpy(path + position, suffix, sizeof(suffix));

        HANDLE handle = CreateFileW(
            path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE |
                FILE_FLAG_SEQUENTIAL_SCAN,
            NULL);
        if (handle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)
                continue;
            errno = EACCES;
            break;
        }
        int descriptor = _open_osfhandle((intptr_t)handle,
                                         _O_BINARY | _O_RDWR);
        if (descriptor < 0) {
            CloseHandle(handle);
            break;
        }
        stream = _fdopen(descriptor, "w+b");
        if (!stream) _close(descriptor);
    }
    free(path);
    free(override_directory);
    if (!stream && errno == 0) errno = EIO;
    return stream;
#else
    const char *directory = getenv("ZUPT_TMPDIR");
    if (!directory || directory[0] == '\0') directory = getenv("TMPDIR");
    if (!directory || directory[0] == '\0') directory = "/tmp";
    static const char suffix[] = "/zupt-restore-XXXXXX";
    size_t directory_length = strlen(directory);
    if (directory_length > SIZE_MAX - sizeof(suffix)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    char *path = (char *)malloc(directory_length + sizeof(suffix));
    if (!path) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(path, directory, directory_length);
    memcpy(path + directory_length, suffix, sizeof(suffix));

    int descriptor = mkstemp(path);
    if (descriptor < 0) {
        free(path);
        return NULL;
    }
    int descriptor_flags = fcntl(descriptor, F_GETFD);
    if (fchmod(descriptor, 0600) != 0 || descriptor_flags < 0 ||
        fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0 ||
        unlink(path) != 0) {
        int saved_errno = errno;
        close(descriptor);
        unlink(path);
        free(path);
        errno = saved_errno;
        return NULL;
    }
    free(path);
    FILE *stream = fdopen(descriptor, "w+b");
    if (!stream) {
        int saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
    }
    return stream;
#endif
}

static FILE *copy_private_restore_snapshot(FILE *source,
                                           uint64_t archive_size) {
    FILE *snapshot = open_private_restore_snapshot();
    if (!snapshot) return NULL;
    uint8_t *buffer = (uint8_t *)malloc(1024u * 1024u);
    if (!buffer) {
        fclose(snapshot);
        errno = ENOMEM;
        return NULL;
    }
    uint64_t remaining = archive_size;
    if (fseeko(source, 0, SEEK_SET) != 0) goto fail;

    while (remaining > 0) {
        size_t wanted = remaining > 1024u * 1024u
                            ? 1024u * 1024u
                            : (size_t)remaining;
        size_t received = fread(buffer, 1, wanted, source);
        if (received == 0) {
            if (errno == 0) errno = EIO;
            goto fail;
        }
        if (fwrite(buffer, 1, received, snapshot) != received) goto fail;
        remaining -= received;
    }
    free(buffer);
    if (fflush(snapshot) != 0 || fseeko(snapshot, 0, SEEK_SET) != 0) {
        int saved_errno = errno ? errno : EIO;
        fclose(snapshot);
        errno = saved_errno;
        return NULL;
    }
    return snapshot;

fail:
    {
        int saved_errno = errno ? errno : EIO;
        free(buffer);
        fclose(snapshot);
        errno = saved_errno;
        return NULL;
    }
}

#if !defined(_WIN32) && \
    (defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__))
/* Query a raw restore target through the already-open descriptor.  Unknown
 * device kinds fail closed: an irreversible restore must know the complete
 * target capacity before its first write. */
static int disk_restore_target_capacity(int descriptor,
                                        const struct stat *info,
                                        uint64_t *capacity) {
    if (!info || !capacity) {
        errno = EINVAL;
        return 0;
    }
#ifdef __linux__
    if (S_ISBLK(info->st_mode)) {
        uint64_t bytes = 0;
        if (ioctl(descriptor, BLKGETSIZE64, &bytes) == 0 && bytes > 0) {
            *capacity = bytes;
            return 1;
        }
    }
#elif defined(__APPLE__)
    if (S_ISBLK(info->st_mode) || S_ISCHR(info->st_mode)) {
        uint64_t block_count = 0;
        uint32_t block_size = 0;
        if (ioctl(descriptor, DKIOCGETBLOCKCOUNT, &block_count) == 0 &&
            ioctl(descriptor, DKIOCGETBLOCKSIZE, &block_size) == 0 &&
            block_count > 0 && block_size > 0 &&
            block_count <= UINT64_MAX / block_size) {
            *capacity = block_count * block_size;
            return 1;
        }
    }
#elif defined(__FreeBSD__)
    if (S_ISCHR(info->st_mode)) {
        off_t media_size = 0;
        if (ioctl(descriptor, DIOCGMEDIASIZE, &media_size) == 0 &&
            media_size > 0) {
            *capacity = (uint64_t)media_size;
            return 1;
        }
    }
#endif
    errno = ENOTSUP;
    return 0;
}
#endif

#ifdef _WIN32
/* Inspect an existing restore target by handle.  The subsequent publication
 * is a handle-relative atomic rename, so a name exchange after this check can
 * only replace that directory entry; it can never make ZUPT follow and
 * truncate an attacker-selected object. */
static int validate_windows_restore_target(
    const char *target_path, const disk_file_identity_t *archive_identity) {
    wchar_t *wide_target = zupt_win_utf8_to_wide_alloc(target_path);
    if (!wide_target) {
        errno = EINVAL;
        return 0;
    }

    HANDLE target_handle = CreateFileW(
        wide_target, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wide_target);
    if (target_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            return 1;
        errno = EACCES;
        return 0;
    }

    BY_HANDLE_FILE_INFORMATION target_info;
    int reported = 0;
    int valid = GetFileInformationByHandle(target_handle, &target_info) != 0;
    if (valid &&
        (target_info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                                         FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        fprintf(stderr,
                "Error: refusing a reparse-point or directory restore target.\n");
        reported = 1;
        valid = 0;
    }
    if (valid && target_info.nNumberOfLinks != 1) {
        fprintf(stderr,
                "Error: refusing a multiply-linked restore target.\n");
        reported = 1;
        valid = 0;
    }
    if (valid &&
        target_info.dwVolumeSerialNumber == archive_identity->volume_serial &&
        target_info.nFileIndexHigh == archive_identity->file_index_high &&
        target_info.nFileIndexLow == archive_identity->file_index_low) {
        fprintf(stderr,
                "Error: archive and restore target are the same file.\n");
        reported = 1;
        valid = 0;
    }
    if (!CloseHandle(target_handle)) valid = 0;
    if (!valid) {
        if (!reported)
            fprintf(stderr, "Error: cannot inspect restore target safely.\n");
        errno = EACCES;
    }
    return valid;
}
#endif

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
    /* Open exactly once: size measurement and reads stay bound to the same
     * file/device even if the source path is exchanged concurrently. */
    FILE *src_f = zupt_fopen_path(source_path, "rb");
    if (!src_f) {
        fprintf(stderr, "Error: Cannot open '%s': %s\n", source_path, strerror(errno));
        return ZUPT_ERR_IO;
    }
    int source_matches_output =
        strcmp(source_path, output_path) == 0
            ? 1
            : disk_source_matches_output(src_f, output_path);
    if (source_matches_output != 0) {
        if (source_matches_output > 0) {
            fprintf(stderr,
                    "Error: disk source and archive output are the same file.\n");
        } else {
            fprintf(stderr,
                    "Error: Cannot inspect disk archive output safely: %s\n",
                    strerror(errno));
        }
        fclose(src_f);
        return source_matches_output > 0 ? ZUPT_ERR_INVALID : ZUPT_ERR_IO;
    }
    int64_t source_size = get_device_size(src_f);
    if (source_size <= 0) {
        fprintf(stderr, "Error: Cannot determine size of '%s': %s\n",
                source_path, strerror(errno));
        fclose(src_f);
        return ZUPT_ERR_IO;
    }

    /* Use 4MB blocks for disk images (good balance of ratio vs memory) */
    if (opts->block_size == 0)
        opts->block_size = 4 * 1024 * 1024;
    if (opts->block_size < ZUPT_MIN_BLOCK_SZ)
        opts->block_size = ZUPT_MIN_BLOCK_SZ;
    {
        uint64_t source_bytes = (uint64_t)source_size;
        uint64_t required_blocks = source_bytes / opts->block_size;
        if (source_bytes % opts->block_size != 0) required_blocks++;
        if (required_blocks > UINT32_MAX) {
            fprintf(stderr,
                    "Error: disk image needs more blocks than the format index can represent.\n");
            fclose(src_f);
            return ZUPT_ERR_OVERFLOW;
        }
    }

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

    /* Build beside the final archive and publish by directory entry only.
     * This prevents a symlink/reparse-point output from being followed. */
    FILE *out = NULL;
    zupt_atomic_output_t *atomic_output =
        zupt_atomic_output_open(output_path, &out);
    if (!atomic_output) {
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
    hdr.global_flags = ZUPT_FLAG_CKSUM_XXH64 | ZUPT_FLAG_DISK_IMAGE |
                       ZUPT_FLAG_DISK_CONTENT_HASH;
    if (opts->encrypt) {
        hdr.global_flags |= ZUPT_FLAG_ENCRYPTED | ZUPT_FLAG_AAD_SEQ |
                            ZUPT_FLAG_AAD_PREFACE;
        opts->keyring.use_preface_aad = 1;
    }
    if (opts->threads > 1) hdr.global_flags |= ZUPT_FLAG_MULTITHREADED;
    if (opts->dedup) hdr.global_flags |= ZUPT_FLAG_DEDUP;
    if (opts->dedup && opts->encrypt)
        hdr.global_flags |= ZUPT_FLAG_AUTH_DEDUP_REFS;
    hdr.creation_time = (uint64_t)time(NULL) * 1000000000ULL;
    zupt_random_bytes(hdr.archive_id, 16);
    hdr.archive_id[6] = (hdr.archive_id[6] & 0x0F) | 0x40;
    hdr.archive_id[8] = (hdr.archive_id[8] & 0x3F) | 0x80;
    if (zupt_write_archive_header(out, &hdr) != 0) write_err = 1;

    /* ─── Encryption header ─── */
    /* ─── Encryption header (uses same code as zupt compress) ─── */
    if (opts->encrypt) {
        zupt_error_t enc_err = write_enc_header(out, &hdr, opts);
        if (enc_err != ZUPT_OK) {
            fclose(src_f);
            zupt_atomic_output_finish(atomic_output, 0);
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
        fclose(src_f);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }

    uint64_t total_read = 0, total_written = 0;
    uint64_t content_hash = 0;
    uint64_t block_seq = 0;
    uint64_t sparse_blocks = 0, data_blocks = 0;
    uint64_t first_block_off = (uint64_t)ftello(out);
    time_t start_time = time(NULL);

    /* Dedup context (NULL if --dedup not set) */
    zupt_dedup_ctx_t *dedup = opts->dedup ? zupt_dedup_init() : NULL;
    if (opts->dedup && !dedup) {
        free(rbuf); free(cbuf);
        fclose(src_f);
        zupt_atomic_output_finish(atomic_output, 0);
        return ZUPT_ERR_NOMEM;
    }

    while (total_read < (uint64_t)source_size) {
        size_t to_read = opts->block_size;
        if (total_read + to_read > (uint64_t)source_size)
            to_read = (size_t)((uint64_t)source_size - total_read);

        size_t nread = fread(rbuf, 1, to_read, src_f);
        if (nread != to_read) {
            fprintf(stderr, "Error: disk source changed or could not be read completely\n");
            write_err = 1;
            break;
        }

        uint64_t checksum = zupt_xxh64(rbuf, nread, 0);
        uint8_t dedup_digest[32];
        if (dedup) zupt_sha256(rbuf, nread, dedup_digest);
        uint64_t logical_aad_seq = block_seq;
        content_hash = zupt_xxh64(rbuf, nread, content_hash);

        /* ─── Dedup check: skip compression if block already written ─── */
        if (dedup) {
            zupt_dedup_record_block(dedup);
            uint64_t ref_off = 0, referenced_aad_seq = 0;
            uint32_t ref_sz = 0;
            if (zupt_dedup_lookup_secure(dedup, checksum, dedup_digest,
                                         &ref_off, &ref_sz,
                                         &referenced_aad_seq) &&
                ref_sz == (uint32_t)nread) {
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
                total_read += nread;
                total_written += opts->encrypt ? 64u : 8u;
                block_seq++;
                if (!opts->quiet)
                    disk_progress("Backup", total_read, (uint64_t)source_size, start_time);
                continue;
            }
        }

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
            uint64_t aad_seq = logical_aad_seq;
            if (opts->keyring.use_preface_aad) {
                uint8_t preface[ZUPT_PREFACE_AAD_LEN];
                uint64_t predicted_size = 16u + payload_size + 32u;
                zupt_serialize_preface_aad_scalars(
                    ZUPT_BLOCK_DATA, codec, ZUPT_BFLAG_ENCRYPTED,
                    nread, predicted_size, checksum, preface);
                enc_payload = zupt_encrypt_buffer_aad(
                    &opts->keyring, payload, payload_size, aad_seq,
                    preface, sizeof(preface), &enc_len);
                zupt_secure_wipe(preface, sizeof(preface));
            } else {
                enc_payload = zupt_encrypt_buffer(
                    &opts->keyring, payload, payload_size, aad_seq, &enc_len);
            }
            if (!enc_payload) {
                free(rbuf); free(cbuf);
                zupt_dedup_free(dedup);
                fclose(src_f);
                zupt_atomic_output_finish(atomic_output, 0);
                return ZUPT_ERR_NOMEM;
            }
            payload = enc_payload;
            payload_size = enc_len;
            bflags |= ZUPT_BFLAG_ENCRYPTED;
        }

        /* Write block: magic + type + codec + flags + uncomp_size + comp_size + checksum + payload */
        uint64_t this_block_off = (uint64_t)ftello(out);
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

        /* Insert into dedup index */
        if (dedup)
            zupt_dedup_insert_secure(dedup, checksum, dedup_digest,
                                     this_block_off, (uint32_t)nread,
                                     logical_aad_seq);

        free(enc_payload);
        total_read += nread;
        total_written += payload_size;
        block_seq++;

        /* Progress */
        if (!opts->quiet)
            disk_progress("Backup", total_read, (uint64_t)source_size, start_time);
    }

    /* ─── Write index (single entry for the disk image) ─── */
    /* SECURITY: size for the worst case — a path clamped to ZUPT_MAX_PATH-1
     * (4095) PLUS the 4-byte file count, the (≤5-byte) varint length, and the
     * 48 bytes of fixed trailing fields. A bare [4096] overflowed by ~57
     * bytes when source_path approached ZUPT_MAX_PATH. */
    uint8_t idx_buf[ZUPT_MAX_PATH + 128];
    size_t idx_pos = 0;

    /* File count uses the same canonical varint representation as regular
     * archives so list/test can parse disk-image archives too. */
    idx_pos += (size_t)zupt_encode_varint(idx_buf + idx_pos, 1);

    /* Path (varint length + bytes) */
    char archive_label[ZUPT_MAX_PATH];
    disk_archive_label(source_path, archive_label);
    size_t path_len = strlen(archive_label);
    idx_pos += (size_t)zupt_encode_varint(idx_buf + idx_pos, path_len);
    memcpy(idx_buf + idx_pos, archive_label, path_len);
    idx_pos += path_len;

    /* Uncompressed size (8B LE) */
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)((uint64_t)source_size >> (i*8));
    /* Compressed size (8B LE) */
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)(total_written >> (i*8));
    /* Modification time (8B LE) */
    uint64_t mtime = (uint64_t)time(NULL) * 1000000000ULL;
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)(mtime >> (i*8));
    /* Content hash (8B LE) */
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)(content_hash >> (i*8));
    /* First block offset (8B LE) */
    for (int i = 0; i < 8; i++) idx_buf[idx_pos++] = (uint8_t)(first_block_off >> (i*8));
    /* Block count (canonical varint) */
    idx_pos += (size_t)zupt_encode_varint(idx_buf + idx_pos, block_seq);
    /* Attributes (4B LE) */
    idx_buf[idx_pos++] = 0; idx_buf[idx_pos++] = 0;
    idx_buf[idx_pos++] = 0; idx_buf[idx_pos++] = 0;

    /* Write index block */
    uint64_t index_offset = (uint64_t)ftello(out);
    uint64_t idx_ck = zupt_xxh64(idx_buf, idx_pos, 0);
    const uint8_t *idx_payload = idx_buf;
    size_t idx_payload_size = idx_pos;
    uint16_t idx_flags = 0;
    uint8_t *encrypted_index = NULL;
    if (opts->encrypt && opts->keyring.active) {
        size_t encrypted_size = 0;
        if (opts->keyring.use_preface_aad) {
            uint8_t preface[ZUPT_PREFACE_AAD_LEN];
            uint64_t predicted_size = 16u + idx_pos + 32u;
            zupt_serialize_preface_aad_scalars(
                ZUPT_BLOCK_INDEX, ZUPT_CODEC_STORE, ZUPT_BFLAG_ENCRYPTED,
                idx_pos, predicted_size, idx_ck, preface);
            encrypted_index = zupt_encrypt_buffer_aad(
                &opts->keyring, idx_buf, idx_pos, UINT64_MAX,
                preface, sizeof(preface), &encrypted_size);
            zupt_secure_wipe(preface, sizeof(preface));
        } else {
            encrypted_index = zupt_encrypt_buffer(
                &opts->keyring, idx_buf, idx_pos, UINT64_MAX,
                &encrypted_size);
        }
        if (!encrypted_index) {
            free(rbuf); free(cbuf);
            zupt_dedup_free(dedup);
            fclose(src_f);
            zupt_atomic_output_finish(atomic_output, 0);
            return ZUPT_ERR_NOMEM;
        }
        idx_payload = encrypted_index;
        idx_payload_size = encrypted_size;
        idx_flags = ZUPT_BFLAG_ENCRYPTED;
    }
    {
        uint8_t bm[2] = {ZUPT_BLOCK_MAGIC_0, ZUPT_BLOCK_MAGIC_1};
        fwrite(bm, 1, 2, out);
        uint8_t bt = ZUPT_BLOCK_INDEX;
        fwrite(&bt, 1, 1, out);
        uint8_t c16[2] = {0, 0}; fwrite(c16, 1, 2, out);
        uint8_t f16[2] = {(uint8_t)(idx_flags & 0xff),
                          (uint8_t)(idx_flags >> 8)};
        fwrite(f16, 1, 2, out);
        zupt_write_varint(out, idx_pos);
        zupt_write_varint(out, idx_payload_size);
        uint8_t ck8[8]; for (int i = 0; i < 8; i++) ck8[i] = (uint8_t)(idx_ck >> (i*8));
        fwrite(ck8, 1, 8, out);
        if (fwrite(idx_payload, 1, idx_payload_size, out) != idx_payload_size)
            write_err = 1;
    }
    free(encrypted_index);

    /* ─── Write footer ─── */
    zupt_footer_t ft;
    uint8_t serialized_header[ZUPT_ARCHIVE_HEADER_SIZE];
    ft.index_offset = index_offset;
    ft.total_blocks = block_seq;
    zupt_serialize_archive_header(&hdr, serialized_header);
    ft.archive_checksum = zupt_xxh64(serialized_header,
                                     sizeof(serialized_header), block_seq);
    ft.footer_magic[0] = 'Z'; ft.footer_magic[1] = 'E';
    ft.footer_magic[2] = 'N'; ft.footer_magic[3] = 'D';
    ft.footer_version = 1;
    if (zupt_write_footer(out, &ft) != 0) write_err = 1;

    /* F-08 of v2.3.0: archive-integrity-trailer.
     *
     * Disk-image archives always pass through opts->keyring just like file
     * archives — the disk path uses the same write_enc_header/keyring setup
     * earlier in this function. opts->encrypt distinguishes encrypted vs
     * plaintext disk images. */
    {
        extern int zupt_format_ait_write(FILE *f, const zupt_archive_header_t *hdr,
                                         const zupt_footer_t *ft,
                                         const zupt_keyring_t *kr_or_null);
        const zupt_keyring_t *kr = opts->encrypt ? &opts->keyring : NULL;
        if (zupt_format_ait_write(out, &hdr, &ft, kr) != 0) {
            fprintf(stderr, "Error: failed to write archive-integrity-trailer\n");
            write_err = 1;
        }
    }

    /* Get final archive size before the atomic close/publication. */
    int64_t final_offset = ftello(out);
    if (final_offset < 0 || ferror(out)) write_err = 1;
    uint64_t out_bytes = final_offset < 0 ? 0 : (uint64_t)final_offset;

    free(rbuf); free(cbuf);
    int64_t final_source_size = get_device_size(src_f);
    if (final_source_size != source_size) {
        fprintf(stderr, "Error: disk source size changed during backup\n");
        write_err = 1;
    }
    if (fclose(src_f) != 0) write_err = 1;
    if (total_read != (uint64_t)source_size) write_err = 1;
    if (zupt_atomic_output_finish(atomic_output, !write_err) != 0)
        write_err = 1;

    if (write_err) {
        fprintf(stderr, "Error: Disk backup failed; the previous archive was preserved.\n");
        zupt_dedup_free(dedup);
        return ZUPT_ERR_IO;
    }

    /* Summary */
    time_t elapsed = time(NULL) - start_time;
    if (elapsed < 1) elapsed = 1;
    char out_sz[16], in_sz[16];

    zupt_format_size((uint64_t)source_size, in_sz, sizeof(in_sz));

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
    if (dedup) {
        uint64_t ds_seen, ds_dedup, ds_saved;
        zupt_dedup_stats(dedup, &ds_seen, &ds_dedup, &ds_saved);
        if (ds_dedup > 0) {
            char sv[32]; zupt_format_size(ds_saved, sv, sizeof(sv));
            fprintf(stderr, "  Dedup:        %llu/%llu blocks (saved %s, %.0f%%)\n",
                    (unsigned long long)ds_dedup, (unsigned long long)ds_seen, sv,
                    ds_seen > 0 ? 100.0 * (double)ds_dedup / (double)ds_seen : 0.0);
        }
    }
    fprintf(stderr, "\n");

    zupt_dedup_free(dedup);
    return ZUPT_OK;
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
    FILE *archive_source = zupt_fopen_path(archive_path, "rb");
    if (!archive_source) {
        fprintf(stderr, "Error: Cannot open '%s': %s\n", archive_path, strerror(errno));
        return ZUPT_ERR_IO;
    }
    disk_file_identity_t archive_identity;
    int64_t signed_archive_size = get_device_size(archive_source);
    if (signed_archive_size <= 0 ||
        !disk_stream_identity(archive_source, &archive_identity)) {
        fprintf(stderr, "Error: Cannot inspect archive '%s': %s\n",
                archive_path, strerror(errno));
        fclose(archive_source);
        return ZUPT_ERR_IO;
    }
    if (!opts->quiet) {
        char archive_size_text[32];
        zupt_format_size((uint64_t)signed_archive_size, archive_size_text,
                         sizeof(archive_size_text));
        fprintf(stderr,
                "  Securing private restore snapshot (%s scratch space)...\n",
                archive_size_text);
    }
    FILE *f = copy_private_restore_snapshot(
        archive_source, (uint64_t)signed_archive_size);
    int snapshot_errno = errno;
    fclose(archive_source);
    if (!f) {
        fprintf(stderr,
                "Error: Cannot create private restore snapshot: %s\n"
                "       Set ZUPT_TMPDIR to a private filesystem with at least "
                "%llu free bytes.\n",
                strerror(snapshot_errno),
                (unsigned long long)signed_archive_size);
        return ZUPT_ERR_IO;
    }

    zupt_archive_header_t hdr;
    zupt_footer_t ft;

    /* Parse and authenticate the central index before opening the restore
     * target.  This supplies the protected byte count/content hash and keeps
     * disk restore aligned with list/test validation. */
    zupt_index_entry_t *disk_entries = NULL;
    int disk_entry_count = 0;
    if (fseeko(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return ZUPT_ERR_IO;
    }
    zupt_error_t index_err = zupt_open_archive_internal(
        f, opts, &hdr, &ft, &disk_entries, &disk_entry_count);
    if (index_err != ZUPT_OK || disk_entry_count != 1 || !disk_entries ||
        !(hdr.global_flags & ZUPT_FLAG_DISK_IMAGE)) {
        free(disk_entries);
        fclose(f);
        fprintf(stderr, "Error: Invalid disk-image index\n");
        return index_err == ZUPT_OK ? ZUPT_ERR_CORRUPT : index_err;
    }
    uint64_t expected_size = disk_entries[0].uncompressed_size;
    uint64_t expected_hash = disk_entries[0].content_hash;
    uint64_t first_data_offset = disk_entries[0].first_block_offset;
    uint32_t expected_blocks = disk_entries[0].block_count;
    free(disk_entries);
    if (expected_blocks != ft.total_blocks || first_data_offset >= ft.index_offset) {
        fclose(f);
        fprintf(stderr, "Error: Invalid disk-image block range\n");
        return ZUPT_ERR_CORRUPT;
    }

    /* A device cannot be rolled back after a late authentication/checksum
     * failure.  Perform the complete read-only archive test on the same
     * private snapshot that restore will consume before opening any target.
     * Regular files also use atomic publication below. */
    {
        int saved_quiet = opts->quiet;
        opts->quiet = 1;
        zupt_error_t preflight = zupt_test_archive_stream(f, opts);
        opts->quiet = saved_quiet;
        if (preflight != ZUPT_OK) {
            fclose(f);
            fprintf(stderr,
                    "Error: disk archive preflight failed; target was not opened.\n");
            return preflight;
        }
    }
    if (fseeko(f, (int64_t)first_data_offset, SEEK_SET) != 0) {
        fclose(f);
        return ZUPT_ERR_IO;
    }

    /* ─── Open target for writing ───
     * Block devices require raw POSIX I/O (open/write) because stdio
     * buffering can cause misaligned or partial writes that corrupt data.
     * O_SYNC ensures each write is flushed to the device before returning.
     * For loop devices, this ensures data reaches the backing file.
     *
     * To avoid TOCTOU races (stat then open on a path that could change),
     * we open the fd first, then fstat on the fd to classify it. */
    FILE *target_stream = NULL;
    zupt_atomic_output_t *target_atomic = NULL;
#ifdef _WIN32
    if (!validate_windows_restore_target(target_path, &archive_identity)) {
        fclose(f);
        return ZUPT_ERR_INVALID;
    }
    target_atomic = zupt_atomic_output_open(target_path, &target_stream);
    if (!target_atomic) {
        fprintf(stderr, "Error: Cannot create target '%s': %s\n",
                target_path, strerror(errno));
        fclose(f);
        return ZUPT_ERR_IO;
    }
#else
    int tgt_fd = -1;
    int is_block_dev = 0;
    /* Resolve the target exactly once before making any type or identity
     * decision.  The open is non-truncating, O_NOFOLLOW rejects a final
     * symlink, and fstat classifies the kernel object that was actually
     * opened.  Device restores retain this same descriptor through the final
     * write, so a concurrent pathname exchange cannot redirect the restore. */
    tgt_fd = open(target_path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC |
                               O_NONBLOCK | O_SYNC);
    if (tgt_fd >= 0) {
        struct stat opened_st;
        if (fstat(tgt_fd, &opened_st) != 0) {
            int saved_errno = errno;
            close(tgt_fd);
            tgt_fd = -1;
            errno = saved_errno;
        } else if (S_ISREG(opened_st.st_mode)) {
            int close_result = close(tgt_fd);
            tgt_fd = -1;
            if (close_result != 0) {
                fclose(f);
                return ZUPT_ERR_IO;
            }
            if (opened_st.st_dev == archive_identity.device &&
                opened_st.st_ino == archive_identity.inode) {
                fprintf(stderr,
                        "Error: archive and restore target are the same file.\n");
                fclose(f);
                return ZUPT_ERR_INVALID;
            }
            if (opened_st.st_nlink != 1) {
                fprintf(stderr,
                        "Error: refusing a multiply-linked restore target.\n");
                fclose(f);
                return ZUPT_ERR_INVALID;
            }
            target_atomic =
                zupt_atomic_output_open(target_path, &target_stream);
        } else if (S_ISBLK(opened_st.st_mode) ||
                   S_ISCHR(opened_st.st_mode)) {
            int flags = fcntl(tgt_fd, F_GETFL);
            if (flags < 0 ||
                fcntl(tgt_fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
                close(tgt_fd);
                tgt_fd = -1;
            } else {
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
                uint64_t target_capacity = 0;
                if (!disk_restore_target_capacity(
                        tgt_fd, &opened_st, &target_capacity)) {
                    fprintf(stderr,
                            "Error: cannot determine restore device "
                            "capacity safely.\n");
                    close(tgt_fd);
                    tgt_fd = -1;
                } else if (expected_size > target_capacity) {
                    fprintf(stderr,
                            "Error: disk image (%llu bytes) exceeds "
                            "restore device capacity (%llu bytes).\n",
                            (unsigned long long)expected_size,
                            (unsigned long long)target_capacity);
                    close(tgt_fd);
                    tgt_fd = -1;
                    errno = EFBIG;
                } else {
                    is_block_dev = 1;
                }
#else
                fprintf(stderr,
                        "Error: restore-device capacity queries are "
                        "not supported on this platform.\n");
                close(tgt_fd);
                tgt_fd = -1;
#endif
            }
        } else {
            close(tgt_fd);
            tgt_fd = -1;
            fprintf(stderr,
                    "Error: restore target is not a regular file or device.\n");
            fclose(f);
            return ZUPT_ERR_INVALID;
        }
    } else if (errno == ENOENT) {
        target_atomic = zupt_atomic_output_open(target_path, &target_stream);
    } else if (errno == ELOOP) {
        fprintf(stderr, "Error: refusing a symbolic-link restore target.\n");
        fclose(f);
        return ZUPT_ERR_INVALID;
    } else {
        fprintf(stderr, "Error: Cannot open target '%s': %s\n",
                target_path, strerror(errno));
        fclose(f);
        return ZUPT_ERR_IO;
    }

    if ((!target_atomic || !target_stream) && tgt_fd < 0) {
        fprintf(stderr, "Error: Cannot open target '%s': %s\n",
                target_path, strerror(errno));
        fclose(f);
        return ZUPT_ERR_IO;
    }
#endif

    int legacy_encrypted_dedup =
        (hdr.global_flags & ZUPT_FLAG_ENCRYPTED) != 0 &&
        (hdr.global_flags & ZUPT_FLAG_DEDUP) != 0 &&
        (hdr.global_flags & ZUPT_FLAG_AUTH_DEDUP_REFS) == 0;
    zupt_legacy_disk_aad_map_t legacy_aad_map = {0};
    if (legacy_encrypted_dedup) {
        zupt_error_t map_error = zupt_legacy_disk_aad_map_build(
            f, first_data_offset, expected_blocks, &legacy_aad_map);
        if (map_error != ZUPT_OK) {
            fprintf(stderr,
                    "Error: cannot map legacy disk dedup authentication positions.\n");
            if (target_atomic) zupt_atomic_output_finish(target_atomic, 0);
#if !defined(_WIN32)
            if (tgt_fd >= 0) close(tgt_fd);
#endif
            fclose(f);
            return map_error;
        }
    }

    fprintf(stderr, "  Restoring disk image to: %s\n", target_path);
    fprintf(stderr, "  Blocks: %llu\n\n", (unsigned long long)ft.total_blocks);

    time_t start_time = time(NULL);
    uint64_t total_written = 0;
    uint64_t restored_hash = 0;
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

        /* Resolve a dedup reference only after authenticating its offset in
         * new archives and proving that it points backward to the expected
         * DATA frame. */
        if (blk.block_type == ZUPT_BLOCK_DEDUP_REF) {
            uint64_t ref_off = 0, referenced_aad_seq = 0;
            int64_t cur = ftello(f);
            int require_authentication =
                (hdr.global_flags & ZUPT_FLAG_AUTH_DEDUP_REFS) != 0;
            zupt_error_t rr = zupt_dedup_read_ref(
                &blk, &opts->keyring, require_authentication,
                require_authentication ? block_seq : 0,
                &ref_off, &referenced_aad_seq);
            if (rr == ZUPT_OK && legacy_encrypted_dedup &&
                !zupt_legacy_disk_aad_map_lookup(
                    &legacy_aad_map, ref_off, &referenced_aad_seq))
                rr = ZUPT_ERR_CORRUPT;
            if (rr != ZUPT_OK || cur < 0 || ref_off >= (uint64_t)cur ||
                fseeko(f, (int64_t)ref_off, SEEK_SET) != 0) {
                free(blk.payload);
                fprintf(stderr, "  Block %llu: invalid dedup reference\n",
                        (unsigned long long)bi);
                errors++;
                break;
            }
            zupt_block_t ref_blk;
            rr = read_block(f, &ref_blk);
            if (fseeko(f, cur, SEEK_SET) != 0 && rr == ZUPT_OK)
                rr = ZUPT_ERR_IO;
            if (rr != ZUPT_OK || ref_blk.block_type != ZUPT_BLOCK_DATA ||
                ref_blk.uncompressed_size != blk.uncompressed_size ||
                ref_blk.checksum != blk.checksum) {
                free(blk.payload);
                free(ref_blk.payload);
                fprintf(stderr, "  Block %llu: dedup ref read error\n",
                        (unsigned long long)bi);
                errors++;
                break;
            }
            free(blk.payload);
            uint8_t *dbuf = NULL; size_t dlen = 0;
            zupt_error_t dr = decompress_block(&ref_blk, &opts->keyring,
                                                referenced_aad_seq,
                                                &dbuf, &dlen);
            free(ref_blk.payload);
            if (dr != ZUPT_OK || total_written > expected_size ||
                (uint64_t)dlen > expected_size - total_written) {
                free(dbuf);
                fprintf(stderr, "  Block %llu: dedup ref decompress failed\n",
                        (unsigned long long)bi);
                errors++;
                break;
            }
            /* Write dedup-resolved data to target */
            int dok = 0;
#ifdef _WIN32
            dok = (fwrite(dbuf, 1, dlen, target_stream) == dlen);
#else
            if (target_stream) {
                dok = (fwrite(dbuf, 1, dlen, target_stream) == dlen);
            } else if (tgt_fd >= 0) {
                size_t dw = 0;
                while (dw < dlen) {
                    ssize_t w = write(tgt_fd, dbuf + dw, dlen - dw);
                    if (w < 0 && errno == EINTR) continue;
                    if (w <= 0) break;
                    dw += (size_t)w;
                }
                dok = (dw == dlen);
            }
#endif
            if (!dok) { fprintf(stderr, "  Block %llu: write error\n", (unsigned long long)bi); free(dbuf); errors++; break; }
            restored_hash = zupt_xxh64(dbuf, dlen, restored_hash);
            total_written += dlen;
            block_seq++;
            free(dbuf);
            if (!opts->quiet && ft.total_blocks > 0)
                disk_progress("Restore", bi + 1, ft.total_blocks, start_time);
            continue;
        }

        if (blk.block_type != ZUPT_BLOCK_DATA) {
            free(blk.payload);
            fprintf(stderr, "  Block %llu: unexpected block type\n",
                    (unsigned long long)bi);
            errors++;
            break;
        }

        /* Decompress + decrypt + verify checksum */
        {
        uint8_t *out_buf = NULL;
        size_t out_len = 0;
        uint64_t aad_seq = block_seq;
        zupt_error_t derr = decompress_block(&blk, &opts->keyring,
                                              aad_seq, &out_buf, &out_len);
        free(blk.payload);

        if (derr == ZUPT_OK &&
            (total_written > expected_size ||
             (uint64_t)out_len > expected_size - total_written))
            derr = ZUPT_ERR_OVERFLOW;
        if (derr != ZUPT_OK) {
            fprintf(stderr, "  Block %llu: decompression/checksum failed (%s)\n",
                    (unsigned long long)bi, zupt_strerror(derr));
            free(out_buf);
            errors++;
            break;
        }

        /* Write to target */
        int write_ok = 0;
#ifdef _WIN32
        write_ok =
            (fwrite(out_buf, 1, out_len, target_stream) == out_len);
#else
        if (target_stream) {
            write_ok =
                (fwrite(out_buf, 1, out_len, target_stream) == out_len);
        } else if (tgt_fd >= 0) {
            size_t written = 0;
            while (written < out_len) {
                ssize_t w = write(tgt_fd, out_buf + written, out_len - written);
                if (w < 0 && errno == EINTR) continue;
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

        restored_hash = zupt_xxh64(out_buf, out_len, restored_hash);
        total_written += out_len;
        block_seq++;
        free(out_buf);

        /* Progress */
        if (!opts->quiet && ft.total_blocks > 0)
            disk_progress("Restore", bi + 1, ft.total_blocks, start_time);
        } /* end decompress scope */
    }

    if (block_seq != expected_blocks || total_written != expected_size) {
        fprintf(stderr, "Error: restored disk size/block count does not match index\n");
        errors++;
    }
    if (hdr.global_flags & ZUPT_FLAG_DISK_CONTENT_HASH) {
        if (restored_hash != expected_hash) {
            fprintf(stderr, "Error: restored disk content hash does not match index\n");
            errors++;
        }
    } else {
        fprintf(stderr, "Warning: legacy disk archive has no full-image content hash.\n");
    }

    if (fclose(f) != 0) errors++;
    if (target_atomic) {
        if (zupt_atomic_output_finish(target_atomic, errors == 0) != 0)
            errors++;
        target_atomic = NULL;
        target_stream = NULL;
    }
#if !defined(_WIN32)
    if (tgt_fd >= 0) {
        if (fsync(tgt_fd) != 0) errors++;
        if (close(tgt_fd) != 0) errors++;
        tgt_fd = -1;
    }
    (void)is_block_dev;
#endif
    zupt_legacy_disk_aad_map_free(&legacy_aad_map);

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
