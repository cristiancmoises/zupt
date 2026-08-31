/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 * ZUPT - CLI v1.5.0
 * Multi-threaded compression, AES-256 encryption, progress bars
 */
#include "zupt.h"
#include "zupt_internal.h"
#include "zupt_thread.h"
#include "zupt_cpuid.h"
#include "vaptvupt.h"  /* VAPTVUPT: codec ID */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>   /* stat()/S_ISREG for the compress output-overwrite guard */

/* MSVC's <sys/stat.h> defines _S_IFREG/S_IFREG but not the S_ISREG macro. */
#ifndef S_ISREG
#  define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

#ifdef _WIN32
  #include <conio.h>
  #include <windows.h>
  #include <winternl.h>
#else
  #include <fcntl.h>
  #include <signal.h>
  #include <termios.h>
#endif

static double zupt_monotonic_seconds(void) {
#ifdef _WIN32
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    if (QueryPerformanceFrequency(&frequency) &&
        frequency.QuadPart > 0 &&
        QueryPerformanceCounter(&counter)) {
        return (double)counter.QuadPart / (double)frequency.QuadPart;
    }
    return (double)GetTickCount64() / 1000.0;
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return (double)time(NULL);
    }
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
#endif
}

static int zupt_join_temp_path(char *output, size_t capacity,
                               const char *directory, const char *leaf) {
    if (!output || !directory || !leaf || capacity == 0) return 0;
    int written = snprintf(output, capacity, "%s%c%s", directory,
                           ZUPT_PATH_SEP, leaf);
    return written >= 0 && (size_t)written < capacity;
}

static int zupt_create_private_temp_directory(char *output, size_t capacity) {
    if (!output || capacity == 0) return 0;
#ifdef _WIN32
    wchar_t temp_directory[MAX_PATH + 1];
    DWORD length = GetTempPathW(MAX_PATH + 1, temp_directory);
    if (length == 0 || length > MAX_PATH || length + 58u > MAX_PATH) return 0;
    static const wchar_t hex[] = L"0123456789abcdef";
    for (int attempt = 0; attempt < 64; attempt++) {
        uint8_t nonce[16];
        wchar_t candidate[MAX_PATH + 1];
        zupt_random_bytes(nonce, sizeof(nonce));
        memcpy(candidate, temp_directory,
               (size_t)length * sizeof(*candidate));
        size_t position = length;
        if (position > 0 && candidate[position - 1] != L'\\' &&
            candidate[position - 1] != L'/')
            candidate[position++] = L'\\';
        const wchar_t prefix[] = L"zupt-bench-";
        memcpy(candidate + position, prefix,
               wcslen(prefix) * sizeof(*candidate));
        position += wcslen(prefix);
        for (size_t i = 0; i < sizeof(nonce); i++) {
            candidate[position++] = hex[nonce[i] >> 4];
            candidate[position++] = hex[nonce[i] & 0x0f];
        }
        candidate[position] = L'\0';
        if (!CreateDirectoryW(candidate, NULL)) {
            DWORD error = GetLastError();
            if (error == ERROR_ALREADY_EXISTS) continue;
            return 0;
        }
        char *utf8 = zupt_win_wide_to_utf8_alloc(candidate);
        if (!utf8 || strlen(utf8) >= capacity) {
            free(utf8);
            RemoveDirectoryW(candidate);
            return 0;
        }
        memcpy(output, utf8, strlen(utf8) + 1u);
        free(utf8);
        return 1;
    }
    return 0;
#else
    char temp_root[ZUPT_MAX_PATH];
    if (!realpath("/tmp", temp_root)) return 0;
    int written = snprintf(output, capacity, "%s/zupt-bench-XXXXXX",
                           temp_root);
    if (written < 0 || (size_t)written >= capacity) return 0;
    if (!mkdtemp(output)) return 0;
    if (chmod(output, 0700) != 0) {
        rmdir(output);
        output[0] = '\0';
        return 0;
    }
    return 1;
#endif
}

#ifdef _WIN32
static void zupt_win_set_cleanup_errno(NTSTATUS status) {
    if (status == (NTSTATUS)0xC0000034L || /* STATUS_OBJECT_NAME_NOT_FOUND */
        status == (NTSTATUS)0xC000003AL) { /* STATUS_OBJECT_PATH_NOT_FOUND */
        errno = ENOENT;
    } else {
        errno = EACCES;
    }
}

/* Open one entry relative to a pinned parent.  Omitting FILE_SHARE_DELETE
 * keeps the name bound to this handle until cleanup finishes; opening the
 * reparse point itself prevents a junction or symlink from redirecting the
 * recursive walk. */
static HANDLE zupt_win_open_cleanup_entry(HANDLE parent,
                                           const wchar_t *name,
                                           int directory_only,
                                           int delete_access) {
    size_t name_length = wcslen(name);
    if (name_length == 0 ||
        name_length > (size_t)USHRT_MAX / sizeof(wchar_t)) {
        errno = ENAMETOOLONG;
        return INVALID_HANDLE_VALUE;
    }
    UNICODE_STRING object_name;
    object_name.Buffer = (PWSTR)name;
    object_name.Length = (USHORT)(name_length * sizeof(wchar_t));
    object_name.MaximumLength = object_name.Length + sizeof(wchar_t);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &object_name,
                               OBJ_CASE_INSENSITIVE, parent, NULL);
    IO_STATUS_BLOCK status_block;
    HANDLE handle = INVALID_HANDLE_VALUE;
    ACCESS_MASK access = FILE_LIST_DIRECTORY | FILE_TRAVERSE |
                         FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    if (delete_access) access |= DELETE;
    ULONG share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    if (delete_access) share |= FILE_SHARE_DELETE;
    ULONG options = FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT;
    if (directory_only) options |= FILE_DIRECTORY_FILE;
    NTSTATUS status = NtCreateFile(
        &handle, access, &attributes, &status_block, NULL,
        FILE_ATTRIBUTE_NORMAL, share, FILE_OPEN,
        options, NULL, 0);
    if (status < 0 || handle == INVALID_HANDLE_VALUE) {
        zupt_win_set_cleanup_errno(status);
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

/* Mark the exact object held by an identity-checked deletion handle. */
static int zupt_win_delete_cleanup_handle(HANDLE handle) {
    FILE_DISPOSITION_INFO disposition;
    disposition.DeleteFile = TRUE;
    if (SetFileInformationByHandle(handle, FileDispositionInfo,
                                   &disposition, sizeof(disposition)))
        return 1;
    errno = EACCES;
    return 0;
}

/* Reopen an emptied child only after closing its no-delete-sharing traversal
 * handle.  Comparing the filesystem identity before marking the new handle
 * for deletion makes a close/reopen name exchange fail safely. */
static int zupt_win_delete_cleanup_entry(
    HANDLE parent, const wchar_t *name,
    const BY_HANDLE_FILE_INFORMATION *expected) {
    HANDLE handle = zupt_win_open_cleanup_entry(parent, name, 1, 1);
    if (handle == INVALID_HANDLE_VALUE) return 0;
    BY_HANDLE_FILE_INFORMATION current;
    int same = GetFileInformationByHandle(handle, &current) &&
               (current.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
               (current.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
               current.dwVolumeSerialNumber == expected->dwVolumeSerialNumber &&
               current.nFileIndexHigh == expected->nFileIndexHigh &&
               current.nFileIndexLow == expected->nFileIndexLow;
    int deleted = same && zupt_win_delete_cleanup_handle(handle);
    int closed = CloseHandle(handle) != 0;
    if (!same) errno = EBUSY;
    return deleted && closed;
}

static int zupt_win_plain_directory(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info;
    return GetFileInformationByHandle(handle, &info) &&
           (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

static int zupt_remove_tree_wide(HANDLE directory_handle,
                                 const wchar_t *directory) {
    size_t directory_length = wcslen(directory);
    wchar_t *pattern = (wchar_t *)calloc(directory_length + 3u,
                                         sizeof(*pattern));
    if (!pattern) return -1;
    memcpy(pattern, directory, directory_length * sizeof(*pattern));
    pattern[directory_length] = L'\\';
    pattern[directory_length + 1u] = L'*';

    WIN32_FIND_DATAW data;
    HANDLE search = FindFirstFileW(pattern, &data);
    DWORD search_error = search == INVALID_HANDLE_VALUE
                             ? GetLastError() : ERROR_SUCCESS;
    free(pattern);
    int failed = 0;
    if (search != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(data.cFileName, L".") == 0 ||
                wcscmp(data.cFileName, L"..") == 0)
                continue;
            size_t name_length = wcslen(data.cFileName);
            wchar_t *child = (wchar_t *)calloc(
                directory_length + name_length + 2u, sizeof(*child));
            if (!child) {
                failed = 1;
                continue;
            }
            memcpy(child, directory, directory_length * sizeof(*child));
            child[directory_length] = L'\\';
            memcpy(child + directory_length + 1u, data.cFileName,
                   (name_length + 1u) * sizeof(*child));
            if (DeleteFileW(child) || RemoveDirectoryW(child)) {
                free(child);
                continue;
            }
            DWORD delete_error = GetLastError();
            if (delete_error == ERROR_FILE_NOT_FOUND ||
                delete_error == ERROR_PATH_NOT_FOUND) {
                free(child);
                continue;
            }
            HANDLE child_handle = zupt_win_open_cleanup_entry(
                directory_handle, data.cFileName, 1, 0);
            if (child_handle == INVALID_HANDLE_VALUE) {
                if (errno != ENOENT) failed = 1;
                free(child);
                continue;
            }
            int child_failed = 0;
            BY_HANDLE_FILE_INFORMATION child_identity;
            if (!GetFileInformationByHandle(child_handle, &child_identity) ||
                (child_identity.dwFileAttributes &
                 FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (child_identity.dwFileAttributes &
                 FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                zupt_remove_tree_wide(child_handle, child) != 0)
                child_failed = 1;
            if (!CloseHandle(child_handle)) child_failed = 1;
            if (!child_failed && !zupt_win_delete_cleanup_entry(
                    directory_handle, data.cFileName, &child_identity))
                child_failed = 1;
            if (child_failed) failed = 1;
            free(child);
        } while (FindNextFileW(search, &data));
        if (GetLastError() != ERROR_NO_MORE_FILES) failed = 1;
        if (!FindClose(search)) failed = 1;
    } else if (search_error != ERROR_FILE_NOT_FOUND) {
        failed = 1;
    }
    return failed ? -1 : 0;
}

/* Resolve the absolute temporary path one component at a time and retain
 * every ancestor handle.  This makes the pathname used for enumeration
 * stable even if another process tries to exchange an ancestor directory. */
static int zupt_win_open_cleanup_path(
    const wchar_t *directory, wchar_t full[ZUPT_MAX_PATH + 256],
    HANDLE **handles_out, size_t *handle_count_out) {
    if (!_wfullpath(full, directory, ZUPT_MAX_PATH + 256)) {
        errno = EINVAL;
        return 0;
    }
    for (wchar_t *p = full; *p; p++) if (*p == L'/') *p = L'\\';
    if ((full[0] == L'\\' && full[1] == L'\\') ||
        !(full[0] && full[1] == L':' && full[2] == L'\\')) {
        errno = EINVAL;
        return 0;
    }

    size_t capacity = wcslen(full) + 1u;
    HANDLE *handles = (HANDLE *)calloc(capacity, sizeof(*handles));
    if (!handles) return 0;
    wchar_t drive_root[4] = {full[0], L':', L'\\', L'\0'};
    HANDLE current = CreateFileW(
        drive_root,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES |
            SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (current == INVALID_HANDLE_VALUE ||
        !zupt_win_plain_directory(current)) {
        DWORD open_error = current == INVALID_HANDLE_VALUE
                               ? GetLastError() : ERROR_ACCESS_DENIED;
        if (current != INVALID_HANDLE_VALUE) CloseHandle(current);
        free(handles);
        errno = open_error == ERROR_FILE_NOT_FOUND ||
                        open_error == ERROR_PATH_NOT_FOUND
                    ? ENOENT : EACCES;
        return 0;
    }
    size_t count = 0;
    handles[count++] = current;

    wchar_t *scan = full + 3;
    while (*scan) {
        wchar_t *separator = wcschr(scan, L'\\');
        if (separator) *separator = L'\0';
        HANDLE next = zupt_win_open_cleanup_entry(
            current, scan, 1, 0);
        if (separator) *separator = L'\\';
        if (next == INVALID_HANDLE_VALUE ||
            !zupt_win_plain_directory(next)) {
            if (next != INVALID_HANDLE_VALUE) CloseHandle(next);
            while (count > 0) CloseHandle(handles[--count]);
            free(handles);
            if (next != INVALID_HANDLE_VALUE) errno = EACCES;
            return 0;
        }
        handles[count++] = next;
        current = next;
        if (!separator) break;
        scan = separator + 1;
    }
    *handles_out = handles;
    *handle_count_out = count;
    return 1;
}
#endif

#ifndef _WIN32
/* Resolve every component without following symlinks and return both the
 * pinned target and its pinned parent.  The caller can therefore remove the
 * final directory with unlinkat() instead of resolving its pathname again. */
static int zupt_open_temp_tree(const char *path, int *parent_out,
                               int *directory_out, char *leaf,
                               size_t leaf_capacity) {
    if (!path || !*path || !parent_out || !directory_out || !leaf ||
        leaf_capacity == 0) {
        errno = EINVAL;
        return 0;
    }
    int current = open(path[0] == '/' ? "/" : ".",
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) return 0;

    const char *cursor = path;
    while (*cursor == '/') cursor++;
    while (*cursor) {
        const char *start = cursor;
        while (*cursor && *cursor != '/') cursor++;
        size_t component_length = (size_t)(cursor - start);
        while (*cursor == '/') cursor++;
        int final_component = *cursor == '\0';
        if ((component_length == 1u && start[0] == '.') ||
            component_length == 0u) {
            if (final_component) {
                close(current);
                errno = EINVAL;
                return 0;
            }
            continue;
        }
        if (component_length == 2u && start[0] == '.' && start[1] == '.') {
            close(current);
            errno = EINVAL;
            return 0;
        }
        if (component_length >= leaf_capacity) {
            close(current);
            errno = ENAMETOOLONG;
            return 0;
        }
        memcpy(leaf, start, component_length);
        leaf[component_length] = '\0';
        int next = openat(current, leaf,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            int saved_errno = errno;
            close(current);
            errno = saved_errno;
            return 0;
        }
        if (final_component) {
            *parent_out = current;
            *directory_out = next;
            return 1;
        }
        close(current);
        current = next;
    }
    close(current);
    errno = EINVAL;
    return 0;
}

/* Delete leaves before attempting to open them as directories.  unlinkat()
 * never follows a symlink; a directory is recursively visited only through
 * an O_NOFOLLOW descriptor returned by openat(). */
static int zupt_remove_temp_tree_fd(int directory_fd) {
    DIR *stream = fdopendir(directory_fd);
    if (!stream) {
        close(directory_fd);
        return -1;
    }
    int failed = 0;
    int parent_fd = dirfd(stream);
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(stream);
        if (!entry) {
            if (errno != 0) failed = 1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (unlinkat(parent_fd, entry->d_name, 0) == 0 || errno == ENOENT)
            continue;

        int child_fd = openat(parent_fd, entry->d_name,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
        if (child_fd < 0) {
            if (errno != ENOENT) failed = 1;
            continue;
        }
        if (zupt_remove_temp_tree_fd(child_fd) != 0) failed = 1;
        if (unlinkat(parent_fd, entry->d_name, AT_REMOVEDIR) != 0 &&
            errno != ENOENT)
            failed = 1;
    }
    if (closedir(stream) != 0) failed = 1;
    return failed ? -1 : 0;
}
#endif

static int zupt_remove_temp_tree(const char *directory) {
    if (!directory || directory[0] == '\0') return 0;
#ifdef _WIN32
    wchar_t *wide = zupt_win_utf8_to_wide_alloc(directory);
    if (!wide) return -1;
    wchar_t full[ZUPT_MAX_PATH + 256];
    HANDLE *handles = NULL;
    size_t handle_count = 0;
    if (!zupt_win_open_cleanup_path(wide, full, &handles, &handle_count)) {
        int result = errno == ENOENT ? 0 : -1;
        free(wide);
        return result;
    }
    HANDLE root_handle = handles[handle_count - 1u];
    int result = zupt_remove_tree_wide(root_handle, full);
    BY_HANDLE_FILE_INFORMATION root_identity;
    if (result == 0 && !GetFileInformationByHandle(root_handle,
                                                    &root_identity))
        result = -1;
    const wchar_t *root_name = wcsrchr(full, L'\\');
    if (!root_name || root_name[1] == L'\0') result = -1;
    else root_name++;
    if (!CloseHandle(handles[--handle_count])) result = -1;
    if (result == 0 && !zupt_win_delete_cleanup_entry(
            handles[handle_count - 1u], root_name, &root_identity))
        result = -1;
    while (handle_count > 0)
        if (!CloseHandle(handles[--handle_count])) result = -1;
    free(handles);
    free(wide);
    return result;
#else
    int parent_fd = -1;
    int directory_fd = -1;
    char leaf[ZUPT_MAX_PATH];
    if (!zupt_open_temp_tree(directory, &parent_fd, &directory_fd,
                             leaf, sizeof(leaf)))
        return errno == ENOENT ? 0 : -1;
    int failed = zupt_remove_temp_tree_fd(directory_fd) != 0;
    if (unlinkat(parent_fd, leaf, AT_REMOVEDIR) != 0 && errno != ENOENT)
        failed = 1;
    if (close(parent_fd) != 0) failed = 1;
    return failed ? -1 : 0;
#endif
}

static int zupt_write_benchmark_corpus(const char *directory) {
    if (zupt_mkdir(directory) != 0) return 0;
    char path[ZUPT_MAX_PATH + 64];
    FILE *stream = NULL;
    int ok = 1;

    if (!zupt_join_temp_path(path, sizeof(path), directory, "text.txt") ||
        !(stream = zupt_fopen_path(path, "wb")))
        return 0;
    for (int i = 0; i < 15000 && ok; i++)
        if (fprintf(stream,
                    "The quick brown fox jumps over the lazy dog. Line %d value %d.\n",
                    i, i * 17 % 997) < 0)
            ok = 0;
    if (fclose(stream) != 0) ok = 0;

    if (!zupt_join_temp_path(path, sizeof(path), directory, "data.json") ||
        !(stream = zupt_fopen_path(path, "wb")))
        return 0;
    for (int i = 0; i < 12000 && ok; i++)
        if (fprintf(stream,
                    "{\"id\":%d,\"name\":\"user_%d\",\"score\":%d}\n",
                    i, i, i * 31 % 1000) < 0)
            ok = 0;
    if (fclose(stream) != 0) ok = 0;

    if (!zupt_join_temp_path(path, sizeof(path), directory, "records.csv") ||
        !(stream = zupt_fopen_path(path, "wb")))
        return 0;
    if (fprintf(stream, "id,name,score\n") < 0) ok = 0;
    for (int i = 0; i < 14000 && ok; i++)
        if (fprintf(stream, "%d,user_%d,%d\n", i, i, i * 17 % 100) < 0)
            ok = 0;
    if (fclose(stream) != 0) ok = 0;

    if (!zupt_join_temp_path(path, sizeof(path), directory, "random.bin") ||
        !(stream = zupt_fopen_path(path, "wb")))
        return 0;
    uint8_t random_bytes[4096];
    for (int i = 0; i < 64 && ok; i++) {
        zupt_random_bytes(random_bytes, sizeof(random_bytes));
        if (fwrite(random_bytes, 1, sizeof(random_bytes), stream) !=
            sizeof(random_bytes))
            ok = 0;
    }
    if (fclose(stream) != 0) ok = 0;
    return ok;
}

static void banner(void) {
    fprintf(stderr,
        "%s %s - %s\n"
        "Format v%d.%d | Codec: VaptVupt + ZUPT-LZ | Checksum: XXH64\n"
        "Encryption: AES-256-CTR + HMAC-SHA256 | KDF: "
#ifdef ZUPT_WITH_SDK
        "Argon2id (default) / PBKDF2 (--kdf pbkdf2)\n\n",
#else
        "PBKDF2-SHA256 (Argon2id needs a WITH_SDK=1 build)\n\n",
#endif
        ZUPT_PRODUCT_NAME, ZUPT_VERSION_STRING, ZUPT_PRODUCT_TAGLINE,
        ZUPT_FORMAT_MAJOR, ZUPT_FORMAT_MINOR);
}

static void usage(void) {
    banner();
    /* usage() text exceeds C99's 4095-char string-literal limit, so we
     * split it into logical sections, one fprintf call per section.
     * Don't merge these back into a single literal — see F-13 in
     * AUDIT.md for the regression test (tests/test_help_consistency.sh)
     * that asserts this. */

    /* ── Section 1: synopsis ── */
    fprintf(stderr,
        "Usage:\n"
        "  zupt compress [OPTIONS] <output.zupt> <files/dirs...>\n"
        "  zupt extract  [OPTIONS] <archive.zupt>\n"
        "  zupt list     [OPTIONS] <archive.zupt>\n"
        "  zupt test     [OPTIONS] <archive.zupt>\n"
        "  zupt info     <archive.zupt>           Archive metadata (no password needed)\n"
        "  zupt bench    <files/dirs...>          Compare levels 1-9\n"
        "  zupt disk     backup|restore            Full-disk backup/restore\n"
        "  zupt keygen                            Key generation\n"
        "  zupt version\n"
        "  zupt help\n"
        "\n"
        "Note: archive extension and format remain .zupt/v1.6.\n"
        "      `zupt` is the primary command. A `vaptvupt` compatibility alias\n"
        "      is optional (INSTALL_LEGACY_ALIAS=1).\n"
        "\n");

    /* ── Section 2: compress options ── */
    fprintf(stderr,
        "Compress Options:\n"
        "  -l, --level <1-9>     Compression level (default: 7)\n"
        "                          1-2: fast, automatic 128 KiB blocks\n"
        "                          3-4: balanced, automatic 1 MiB blocks\n"
        "                          5-6: high, automatic 2 MiB blocks\n"
        "                          7: default, automatic 4 MiB blocks\n"
        "                          8-9: maximum, automatic 8 MiB blocks\n"
        "  -b, --block <SIZE>    Override the automatic block size in bytes\n"
        "  -s, --store           Store without compression\n"
        "  -f, --fast            Use fast LZ codec (less compression)\n"
        "      Default codec: automatic; VaptVupt LZ + ANS on AVX2/NEON,\n"
        "      with portable ZUPT-LZHP fallback on other CPUs.\n"
        "  --vv, --vaptvupt      Force VaptVupt codec (LZ + ANS entropy)\n"
        "  --lzhp                Use ZUPT-LZHP codec (LZ77+Huffman, no SIMD needed)\n"
        "  -p, --password <PW>   Encrypt with AES-256 (visible in process arguments)\n"
        "  --password-prompt     Read the password interactively without echo\n"
        "  --pass-file <FILE>    Read the password from the first line of FILE\n"
        "  --pass-fd <FD>        Read the password from an inherited file descriptor\n"
        "                          All options must precede <output.zupt>.\n"
#ifdef ZUPT_WITH_SDK
        "  --kdf <argon2id|pbkdf2>   KDF for password mode. Default: argon2id.\n"
        "                            Use 'pbkdf2' for v2.4.0-and-older reader compatibility.\n"
#else
        "  --kdf <pbkdf2>            KDF for password mode. Default (and only, this build):\n"
        "                            PBKDF2-SHA256 600k. Argon2id needs a WITH_SDK=1 build.\n"
#endif
        "  -c, --comment <TEXT>  Embed a free-form archive comment (v2.4.3+).\n"
        "  --comment-file <FILE>     Read comment from file (max 4096 bytes).\n"
        "  --pq <pubkey>         Post-quantum HYBRID encryption (ML-KEM-768 + X25519) [recommended]\n"
        "  --pq-only <pubkey>    FULL post-quantum encryption (ML-KEM-768 only, no classical layer)\n"
        "  --pq-sdk <pubkey>     Post-quantum encryption via libvuptsdk (WITH_SDK=1 builds only)\n"
        "  --pq-box <pubkey>     Post-quantum sealed box via libpqvaptvupt (WITH_PQBOX=1 builds only)\n"
        "  --dedup, -D           Block-level deduplication\n"
        "  --solid               Solid mode (single stream)\n"
        "  -y, --force           Overwrite an existing non-.zupt file as the output archive\n"
        "  -v, --verbose         Verbose per-file output\n"
        "  -t, --threads <N>     Thread count (0=auto, 1=single, 2-64=explicit)\n"
        "\n");

    /* ── Section 3: extract/list/test options ── */
    fprintf(stderr,
        "Extract/List/Test Options:\n"
        "  -o, --output <DIR>    Output directory (extract only)\n"
        "  -p, --password <PW>   Decryption password (visible in process arguments)\n"
        "  --password-prompt     Read the password interactively without echo\n"
        "  --pass-file <FILE>    Read the password from the first line of FILE\n"
        "  --pass-fd <FD>        Read the password from an inherited file descriptor\n"
        "  --pq <privkey>        Post-quantum HYBRID decryption (ML-KEM-768 + X25519)\n"
        "  --pq-only <privkey>   FULL post-quantum decryption (ML-KEM-768 only)\n"
        "  --pq-sdk <privkey>    Post-quantum decryption via libvuptsdk (WITH_SDK=1 builds only)\n"
        "  --pq-box <privkey>    Post-quantum sealed-box decryption (libpqvaptvupt)\n"
        "  --allow-legacy-no-ait  Accept a trusted old archive without its integrity trailer\n"
        "  -v, --verbose         Verbose output\n"
        "  -t, --threads <N>     Thread count for decompression\n"
        "\n"
        "Keygen Options:\n"
        "  -o <file>             Output keyfile path (required)\n"
        "  --pub                 Export public key from existing private key (-k)\n"
        "  -k <privkey>          Source private keyfile (with --pub)\n"
        "  (default)             Generate HYBRID keypair (ML-KEM-768 + X25519) for --pq\n"
        "  --pq-only             Generate FULL post-quantum keypair (ML-KEM-768 only) for --pq-only\n"
        "  --sdk, --pq-sdk       Generate SDK v2 keypair (libvuptsdk; WITH_SDK=1 builds only)\n"
        "  --box, --pq-box       Generate pq-box keypair (libpqvaptvupt; WITH_PQBOX=1 builds only)\n"
        "                          Use each key with its matching mode.\n"
        "\n"
        "Directories are traversed recursively.\n"
        "\n");

    /* ── Section 4: examples ── */
    fprintf(stderr,
        "Examples:\n"
        "  # Post-quantum HYBRID workflow (--pq, recommended)\n"
        "  zupt keygen -o mykey.key                                   # Generate hybrid private key\n"
        "  zupt keygen --pub -o pub.key -k mykey.key                  # Export public key\n"
        "  zupt compress --pq pub.key backup.zupt ~/Documents/        # Encrypt\n"
        "  zupt extract  --pq mykey.key backup.zupt -o ~/restored/    # Decrypt\n"
        "\n"
        "  # Full (pure) post-quantum workflow (--pq-only, ML-KEM-768 only)\n"
        "  zupt keygen --pq-only -o pqkey                            # Generate pq-only private key\n"
        "  zupt keygen --pub --pq-only -o pqkey.pub -k pqkey          # Export public key\n"
        "  zupt compress --pq-only pqkey.pub backup.zupt files/       # Encrypt (no classical layer)\n"
        "  zupt extract  --pq-only pqkey backup.zupt -o out/          # Decrypt\n"
        "\n"
        "  # Conventional / password (PBKDF2-SHA256)\n"
        "  zupt compress backup.zupt ~/Documents/                     # No encryption\n"
        "  zupt compress -l 9 -p mysecret secure.zupt data/           # Password + max compression\n"
        "  zupt list secure.zupt -p mysecret                          # List with password\n"
        "  zupt extract -o restored/ -p mysecret secure.zupt          # Extract with password\n"
        "  zupt bench ~/Documents/                                # Benchmark\n"
        "\n"
        "  # Optional modes require system development packages at build time:\n"
        "  #   WITH_SDK=1: keygen --sdk, compress/extract --pq-sdk\n"
        "  #   WITH_PQBOX=1: keygen --box, compress/extract --pq-box\n"
        "\n");

    /* ── Section 5: footer ── */
    fprintf(stderr,
        "Default codec: Auto (VaptVupt " ZUPT_CODEC_RELEASE " with AVX2/NEON; LZHP fallback)\n"
        "Encryption:    AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC)\n"
#ifdef ZUPT_WITH_SDK
        "KDF:           Argon2id (default); PBKDF2-SHA256 600k iter via --kdf pbkdf2\n"
#else
        "KDF:           PBKDF2-SHA256 600k iter (default; Argon2id needs WITH_SDK=1)\n"
#endif
        "Post-quantum:  --pq (hybrid ML-KEM-768 + X25519, recommended); --pq-only (ML-KEM-768 only)\n"
        "Format:        v1.6; 5.2.2 adds flag-gated disk/dedup records\n"
        "\n"
        "License: AGPL-3.0-or-later (ZUPT) + GPL-3.0-or-later (codec)\n"
        "         + BSD-2-Clause (xxHash-derived XXH64 routines)\n"
        "         + CC0-1.0 (pq-crystals/kyber-derived ML-KEM portions)\n"
        "         + BSD-3-Clause (curve25519-donna-derived X25519 portions)\n"
        "         Commercial terms may be available by agreement: sac@securityops.co\n"
        "Project: https://github.com/cristiancmoises/zupt\n"
    );
}

#ifndef _WIN32
static volatile sig_atomic_t zupt_password_prompt_signal;

static void zupt_password_prompt_interrupted(int signal_number) {
    zupt_password_prompt_signal = signal_number;
}
#endif

/* Securely prompt for password (hide input). */
static int prompt_password(const char *prompt, char *buf, size_t cap) {
    if (!buf || cap < 2) return 0;
    buf[0] = '\0';
#ifdef _WIN32
    HANDLE input_handle = GetStdHandle(STD_INPUT_HANDLE);
    DWORD input_mode = 0;
    if (input_handle == NULL || input_handle == INVALID_HANDLE_VALUE ||
        GetFileType(input_handle) != FILE_TYPE_CHAR ||
        !GetConsoleMode(input_handle, &input_mode)) {
        fprintf(stderr, "Error: password prompt requires a terminal.\n");
        return 0;
    }
#else
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "Error: password prompt requires a terminal.\n");
        return 0;
    }
#endif
    fprintf(stderr, "%s", prompt);
#ifdef _WIN32
    size_t i = 0;
    int too_long = 0;
    for (;;) {
        int c = _getch();
        if (c == EOF) {
            zupt_secure_wipe(buf, cap);
            fprintf(stderr, "\nError: cannot read password prompt.\n");
            return 0;
        }
        if (c == '\r' || c == '\n') break;
        if (c == 0 || c == 0xe0) {
            (void)_getch();
            continue;
        }
        if (c == 3) {
            zupt_secure_wipe(buf, cap);
            fprintf(stderr, "\nError: password prompt interrupted.\n");
            return 0;
        }
        if (c == '\b') {
            if (i > 0) i--;
            continue;
        }
        if (i < cap - 1) buf[i++] = (char)c;
        else too_long = 1;
    }
    buf[i] = '\0';
    fprintf(stderr, "\n");
    if (too_long) {
        fprintf(stderr, "Error: password exceeds %zu bytes.\n", cap - 1);
        zupt_secure_wipe(buf, cap);
        return 0;
    }
    return i > 0;
#else
    struct termios old, new_t;
    static const int prompt_signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
    struct sigaction previous[sizeof(prompt_signals) / sizeof(prompt_signals[0])];
    struct sigaction temporary;
    sigset_t prompt_signal_mask, previous_signal_mask;
    size_t handlers_installed = 0;
    if (tcgetattr(STDIN_FILENO, &old) != 0) {
        fprintf(stderr, "\nError: cannot configure terminal input.\n");
        return 0;
    }
    memset(&temporary, 0, sizeof(temporary));
    temporary.sa_handler = zupt_password_prompt_interrupted;
    sigemptyset(&prompt_signal_mask);
    for (size_t index = 0;
         index < sizeof(prompt_signals) / sizeof(prompt_signals[0]);
         index++)
        (void)sigaddset(&prompt_signal_mask, prompt_signals[index]);
    temporary.sa_mask = prompt_signal_mask;
    zupt_password_prompt_signal = 0;
    for (size_t index = 0;
         index < sizeof(prompt_signals) / sizeof(prompt_signals[0]);
         index++) {
        if (sigaction(prompt_signals[index], &temporary,
                      &previous[index]) != 0) {
            while (handlers_installed > 0) {
                handlers_installed--;
                (void)sigaction(prompt_signals[handlers_installed],
                                &previous[handlers_installed], NULL);
            }
            fprintf(stderr, "\nError: cannot protect terminal state.\n");
            return 0;
        }
        handlers_installed++;
    }
    new_t = old;
    /* Clear the ECHO bit. ~ECHO is `int` (negative); c_lflag is
     * tcflag_t (unsigned int). The cast makes the conversion
     * explicit and silences -Wsign-conversion. */
    new_t.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_t) != 0) {
        while (handlers_installed > 0) {
            handlers_installed--;
            (void)sigaction(prompt_signals[handlers_installed],
                            &previous[handlers_installed], NULL);
        }
        fprintf(stderr, "\nError: cannot disable terminal echo.\n");
        return 0;
    }
    int ok = 0;
    int too_long = 0;
    if (zupt_password_prompt_signal == 0 && fgets(buf, (int)cap, stdin)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len-1] == '\n') {
            buf[len-1] = '\0';
        } else {
            int ch = fgetc(stdin);
            if (ch != '\n' && ch != EOF) {
                too_long = 1;
                while ((ch = fgetc(stdin)) != '\n' && ch != EOF) {}
            }
            if (ferror(stdin)) too_long = 1;
        }
        ok = buf[0] != '\0';
    }
    /* Block every handled prompt signal while restoring terminal state and
     * the caller's handlers. Otherwise a second signal can interrupt the one
     * tcsetattr attempt or land between the signal snapshot and restoration,
     * leaving echo disabled or swallowing the later signal. */
    int signals_blocked =
        sigprocmask(SIG_BLOCK, &prompt_signal_mask, &previous_signal_mask) == 0;
    if (!signals_blocked) ok = 0;
    int terminal_restore_status;
    do {
        terminal_restore_status = tcsetattr(STDIN_FILENO, TCSANOW, &old);
    } while (terminal_restore_status != 0 && errno == EINTR);
    if (terminal_restore_status != 0) ok = 0;
    int interrupted_by = (int)zupt_password_prompt_signal;
    while (handlers_installed > 0) {
        handlers_installed--;
        if (sigaction(prompt_signals[handlers_installed],
                      &previous[handlers_installed], NULL) != 0)
            ok = 0;
    }
    if (signals_blocked &&
        sigprocmask(SIG_SETMASK, &previous_signal_mask, NULL) != 0)
        ok = 0;
    fprintf(stderr, "\n");
    if (interrupted_by != 0) {
        zupt_secure_wipe(buf, cap);
        fprintf(stderr, "Error: password prompt interrupted.\n");
        (void)raise(interrupted_by);
        errno = EINTR;
        return 0;
    }
    if (too_long) {
        fprintf(stderr, "Error: password exceeds %zu bytes.\n", cap - 1);
        zupt_secure_wipe(buf, cap);
        ok = 0;
    }
    return ok;
#endif
}

static int read_password_stream(FILE *stream, const char *source,
                                char *password, size_t capacity) {
    if (!stream || !password || capacity < 2) return 0;
    size_t length = 0;
    int ch;
    int too_long = 0;
    while ((ch = fgetc(stream)) != EOF && ch != '\n') {
        if (ch == '\0') {
            fprintf(stderr, "Error: %s contains a NUL byte.\n", source);
            zupt_secure_wipe(password, capacity);
            return 0;
        }
        if (length + 1 >= capacity) {
            too_long = 1;
            continue;
        }
        password[length++] = (char)ch;
    }
    if (ferror(stream) || too_long) {
        fprintf(stderr, "Error: cannot read %s or password exceeds %zu bytes.\n",
                source, capacity - 1);
        zupt_secure_wipe(password, capacity);
        return 0;
    }
    if (length > 0 && password[length - 1] == '\r') length--;
    password[length] = '\0';
    if (length == 0) {
        fprintf(stderr, "Error: %s contains an empty password.\n", source);
        return 0;
    }
    return 1;
}

/* Parse the non-argv password sources shared by every encrypted command.
 * Return 0 when argv[*index] is unrelated, 1 on success, and -1 on error. */
static int parse_password_source(int argc, char **argv, int *index,
                                 zupt_options_t *opts, int confirm) {
    const char *option = argv[*index];
    if (strcmp(option, "--password-prompt") == 0) {
        opts->encrypt = 1;
        if (!prompt_password("Password: ", opts->password,
                             sizeof(opts->password))) {
            fprintf(stderr, "Error: password cannot be empty.\n");
            return -1;
        }
        if (confirm) {
            char confirmation[sizeof(opts->password)];
            if (!prompt_password("Confirm:  ", confirmation,
                                 sizeof(confirmation))) {
                zupt_secure_wipe(confirmation, sizeof(confirmation));
                return -1;
            }
            int matches = strcmp(opts->password, confirmation) == 0;
            zupt_secure_wipe(confirmation, sizeof(confirmation));
            if (!matches) {
                fprintf(stderr, "Error: Passwords do not match.\n");
                zupt_secure_wipe(opts->password, sizeof(opts->password));
                return -1;
            }
        }
        return 1;
    }
    if (strcmp(option, "--pass-file") == 0) {
        if (*index + 1 >= argc) {
            fprintf(stderr, "Error: --pass-file requires a path.\n");
            return -1;
        }
        const char *path = argv[++*index];
        FILE *stream = zupt_fopen_path(path, "rb");
        if (!stream) {
            fprintf(stderr, "Error: cannot open password file '%s'.\n", path);
            return -1;
        }
        opts->encrypt = 1;
        int ok = read_password_stream(stream, "password file",
                                      opts->password, sizeof(opts->password));
        if (fclose(stream) != 0) ok = 0;
        return ok ? 1 : -1;
    }
    if (strcmp(option, "--pass-fd") == 0) {
        if (*index + 1 >= argc) {
            fprintf(stderr, "Error: --pass-fd requires a descriptor number.\n");
            return -1;
        }
        char *end = NULL;
        errno = 0;
        long descriptor = strtol(argv[++*index], &end, 10);
        if (errno || !end || *end != '\0' || descriptor < 0 ||
            descriptor > INT_MAX) {
            fprintf(stderr, "Error: invalid descriptor for --pass-fd.\n");
            return -1;
        }
#ifdef _WIN32
        int duplicate = _dup((int)descriptor);
#else
        int duplicate = dup((int)descriptor);
#endif
        if (duplicate < 0) {
            fprintf(stderr, "Error: cannot duplicate --pass-fd descriptor.\n");
            return -1;
        }
#ifdef _WIN32
        FILE *stream = _fdopen(duplicate, "rb");
#else
        FILE *stream = fdopen(duplicate, "rb");
#endif
        if (!stream) {
#ifdef _WIN32
            _close(duplicate);
#else
            close(duplicate);
#endif
            fprintf(stderr, "Error: cannot read --pass-fd descriptor.\n");
            return -1;
        }
        opts->encrypt = 1;
        int ok = read_password_stream(stream, "password descriptor",
                                      opts->password, sizeof(opts->password));
        if (fclose(stream) != 0) ok = 0;
        return ok ? 1 : -1;
    }
    return 0;
}

static int streq(const char *a, const char *b) { return strcmp(a,b)==0; }
static int isopt(const char *a) { return a[0]=='-'; }

static int zupt_cli_main(int argc, char **argv) {
    /* Detect CPU features (AES-NI, AVX2) at startup */
    zupt_detect_cpu(&zupt_cpu);

    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    if (streq(cmd,"help")||streq(cmd,"--help")||streq(cmd,"-h")) { usage(); return 0; }
    if (streq(cmd,"version")||streq(cmd,"--version")||streq(cmd,"-V")) {
        printf("zupt %s (ZUPT)\n"
               "Format: v%d.%d | Archive extension: .zupt (unchanged)\n"
               "Codec: VaptVupt " ZUPT_CODEC_RELEASE " (0x%04X) — LZ + ANS, optimal parser + large-window extreme\n"
               "Encryption: AES-256-CTR + HMAC-SHA256\n"
#ifdef ZUPT_WITH_SDK
               "KDF: Argon2id (default) / PBKDF2-SHA256 %d iter (--kdf pbkdf2)\n"
#else
               "KDF: PBKDF2-SHA256 %d iter (default; Argon2id needs WITH_SDK=1)\n"
#endif
               "Post-quantum: --pq hybrid (ML-KEM-768 + X25519), --pq-only (ML-KEM-768 only)"
#ifdef ZUPT_WITH_SDK
               ", --pq-sdk (libvuptsdk)"
#endif
#ifdef ZUPT_WITH_PQBOX
               ", --pq-box (libpqvaptvupt)"
#endif
               "\n"
               "Build integrations: libvuptsdk="
#ifdef ZUPT_WITH_SDK
               "enabled"
#else
               "disabled"
#endif
               ", libpqvaptvupt="
#ifdef ZUPT_WITH_PQBOX
               "enabled\n"
#else
               "disabled\n"
#endif
               "License: AGPL-3.0-or-later (ZUPT) + GPL-3.0-or-later (codec)\n"
               "         + BSD-2-Clause (xxHash-derived XXH64 routines)\n"
               "         + CC0-1.0 (pq-crystals/kyber-derived ML-KEM portions)\n"
               "         + BSD-3-Clause (curve25519-donna-derived X25519 portions)\n"
               "         Commercial terms may be available by agreement\n"
               "Project: https://github.com/cristiancmoises/zupt\n"
               "Commercial: sac@securityops.co\n",
               ZUPT_VERSION_STRING, ZUPT_FORMAT_MAJOR, ZUPT_FORMAT_MINOR,
               ZUPT_CODEC_VAPTVUPT, ZUPT_KDF_ITERATIONS);
        /* Runtime crypto hardware acceleration (reflects this CPU). */
        printf("HW accel (this CPU):");
        int any = 0;
        if (zupt_cpu.has_aesni && zupt_cpu.has_avx) { printf(" AES-NI"); any = 1; }
        if (zupt_cpu.has_shani)                     { printf(" SHA-NI"); any = 1; }
        if (zupt_cpu.has_avx2)                      { printf(" AVX2(codec)"); any = 1; }
        printf("%s\n", any ? "" : " none (portable C fallback)");
        return 0;
    }

    /* ─── info ─── */
    if (streq(cmd,"info")||streq(cmd,"i")) {
        if (argc < 3) { fprintf(stderr, "Error: info requires <archive.zupt>\n"); return 1; }
        return zupt_archive_info(argv[2]) != ZUPT_OK ? 1 : 0;
    }

    /* ─── compress ─── */
    if (streq(cmd,"compress")||streq(cmd,"c")) {
        zupt_options_t opts; zupt_default_options(&opts);
        int ai = 2;
        int force = 0;  /* -y/--force: allow overwriting a non-.zupt output */
        while (ai<argc && isopt(argv[ai])) {
            int password_source = parse_password_source(
                argc, argv, &ai, &opts, 1);
            if (password_source < 0) return 1;
            if (password_source > 0) { ai++; continue; }
            if ((streq(argv[ai],"-l")||streq(argv[ai],"--level"))&&ai+1<argc) {
                opts.level=atoi(argv[++ai]); if(opts.level<1)opts.level=1; if(opts.level>9)opts.level=9;
            } else if ((streq(argv[ai],"-b")||streq(argv[ai],"--block"))&&ai+1<argc) {
                opts.block_size=(uint32_t)atol(argv[++ai]);
                if(opts.block_size<ZUPT_MIN_BLOCK_SZ)opts.block_size=ZUPT_MIN_BLOCK_SZ;
                if(opts.block_size>ZUPT_MAX_BLOCK_SZ)opts.block_size=ZUPT_MAX_BLOCK_SZ;
            } else if (streq(argv[ai],"-s")||streq(argv[ai],"--store")) {
                opts.codec_id=ZUPT_CODEC_STORE;
            } else if (streq(argv[ai],"-f")||streq(argv[ai],"--fast")) {
                opts.codec_id=ZUPT_CODEC_ZUPT_LZ;
            } else if (streq(argv[ai],"--vv")||streq(argv[ai],"--vaptvupt")) {
                opts.codec_id=ZUPT_CODEC_VAPTVUPT; /* VAPTVUPT */
            } else if (streq(argv[ai],"--lzhp")) {
                opts.codec_id=ZUPT_CODEC_ZUPT_LZHP;
            } else if (streq(argv[ai],"-p")||streq(argv[ai],"--password")) {
                opts.encrypt=1;
                if (ai+1<argc && !isopt(argv[ai+1])) {
                    strncpy(opts.password, argv[++ai], sizeof(opts.password)-1);
                } else {
                    if (!prompt_password("Password: ", opts.password,
                                         sizeof(opts.password))) return 1;
                    char confirm[256];
                    if (!prompt_password("Confirm:  ", confirm,
                                         sizeof(confirm))) {
                        zupt_secure_wipe(opts.password, sizeof(opts.password));
                        return 1;
                    }
                    if (strcmp(opts.password, confirm)!=0) {
                        zupt_secure_wipe(confirm, sizeof(confirm));
                        fprintf(stderr, "Error: Passwords do not match.\n"); return 1;
                    }
                    zupt_secure_wipe(confirm, sizeof(confirm));
                }
            } else if (streq(argv[ai],"-v")||streq(argv[ai],"--verbose")) {
                zupt_internal_set_verbose(&opts);
            } else if (streq(argv[ai],"--solid")||streq(argv[ai],"-S")) {
                opts.solid=1;
            } else if ((streq(argv[ai],"-t")||streq(argv[ai],"--threads"))&&ai+1<argc) {
                opts.threads=atoi(argv[++ai]);
                if(opts.threads<0)opts.threads=0;
                if(opts.threads>ZUPT_MAX_THREADS)opts.threads=ZUPT_MAX_THREADS;
            } else if (streq(argv[ai],"--pq-box")&&ai+1<argc) {
                opts.pq_mode=1; opts.box_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq-sdk")&&ai+1<argc) {
                opts.pq_mode=1; opts.sdk_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq-only")&&ai+1<argc) {
                opts.pqonly_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq")&&ai+1<argc) {
                opts.pq_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--dedup")||streq(argv[ai],"-D")) {
                opts.dedup=1;
            } else if ((streq(argv[ai],"-c")||streq(argv[ai],"--comment"))&&ai+1<argc) {
                /* v2.4.3: free-form archive comment. Encrypted along with
                 * data blocks when -p/--pq is also set. */
                ai++;
                strncpy(opts.comment, argv[ai], ZUPT_MAX_COMMENT_LEN - 1);
                opts.comment[ZUPT_MAX_COMMENT_LEN - 1] = '\0';
                opts.has_comment = 1;
            } else if (streq(argv[ai],"--comment-file")&&ai+1<argc) {
                ai++;
                FILE *cf = zupt_fopen_path(argv[ai], "rb");
                if (!cf) {
                    fprintf(stderr, "Error: --comment-file: cannot open '%s'\n", argv[ai]);
                    return 1;
                }
                size_t n = fread(opts.comment, 1, ZUPT_MAX_COMMENT_LEN - 1, cf);
                opts.comment[n] = '\0';
                while (n > 0 && (opts.comment[n-1] == '\n' || opts.comment[n-1] == '\r')) {
                    opts.comment[--n] = '\0';
                }
                opts.has_comment = (n > 0);
                fclose(cf);
            } else if (streq(argv[ai],"--kdf")&&ai+1<argc) {
                /* Argon2id is supplied only by the optional system SDK.
                 * Never silently downgrade an explicit request to PBKDF2. */
                ai++;
                if (streq(argv[ai],"pbkdf2")) {
                    opts.kdf_legacy_pbkdf2 = 1;
                } else if (streq(argv[ai],"argon2id") || streq(argv[ai],"argon2")) {
#ifdef ZUPT_WITH_SDK
                    opts.kdf_legacy_pbkdf2 = 0;
#else
                    fprintf(stderr,
                        "Error: --kdf argon2id requires a WITH_SDK=1 build with system libvuptsdk.\n");
                    return 1;
#endif
                } else {
                    fprintf(stderr, "Error: unsupported --kdf value '%s'.\n", argv[ai]);
                    return 1;
                }
            } else if (streq(argv[ai],"-y")||streq(argv[ai],"--force")) {
                force = 1;
            } else {
                fprintf(stderr,"Error: Unknown option '%s'\n",argv[ai]); return 1;
            }
            ai++;
        }
        if (argc-ai<2) {
            fprintf(stderr,"Error: compress requires <output.zupt> <files/dirs...>\n"); return 1;
        }
        const char *output = argv[ai++];

        /* Reject a misplaced option among the file positionals. Without this,
         * `compress out.zupt dir -p secret` silently treats "-p"/"secret" as
         * (skipped) input files and writes an UNENCRYPTED archive with exit 0
         * — the user believes it is encrypted. Options must precede the
         * output archive (use `--` before a real filename that starts with '-'). */
        int seen_dashdash = 0;
        for (int i=ai; i<argc; i++) {
            if (!seen_dashdash && streq(argv[i],"--")) { seen_dashdash = 1; continue; }
            if (!seen_dashdash && isopt(argv[i])) {
                fprintf(stderr,
                    "Error: option '%s' appears after the output archive.\n"
                    "       In compress, all options (including -p/--pq) must come BEFORE\n"
                    "       the output archive name. Example:\n"
                    "         zupt compress -p PASSWORD %s %s ...\n",
                    argv[i], output, (i>ai ? argv[ai] : "<files>"));
                return 1;
            }
        }

        /* Data-loss guard. `compress -p out.zupt a.txt b.txt` makes -p swallow
         * "out.zupt" as the PASSWORD, shifts positionals so the output archive
         * becomes "a.txt", and truncates a.txt (a user data file) with archive
         * bytes — silently, exit 0. Refuse to overwrite an existing regular file
         * that is not a .zupt archive unless -y/--force is given. Archives the
         * tool writes end in .zupt, so this never blocks normal use. */
        {
            size_t olen = strlen(output);
            int is_zupt = (olen >= 5 && strcmp(output + olen - 5, ".zupt") == 0);
            if (!force && !is_zupt && zupt_is_regular_file(output)) {
                fprintf(stderr,
                    "Error: refusing to overwrite existing file '%s' as the output archive\n"
                    "       (it does not end in .zupt). If you meant to set a password, use\n"
                    "       '-p<password>' or put '-p PASSWORD' BEFORE the archive name.\n"
                    "       Pass -y/--force to overwrite '%s' anyway.\n",
                    output, output);
                return 1;
            }
        }

        /* Skip a leading `--` separator before the file list. */
        if (ai < argc && streq(argv[ai], "--")) ai++;

        /* Collect files (expand directories recursively). Guard against the
         * output archive also being one of the inputs (self-overwrite). */
        zupt_filelist_t fl; zupt_filelist_init(&fl);
        for (int i=ai; i<argc; i++) {
            if (streq(argv[i], output)) {
                fprintf(stderr, "Error: input '%s' is the same as the output archive.\n", argv[i]);
                zupt_filelist_free(&fl); return 1;
            }
            zupt_collect_files(&fl, argv[i], argv[i]);
        }

        if (zupt_internal_filelist_failed(&fl)) {
            fprintf(stderr, "Error: input collection was incomplete; archive was not created.\n");
            zupt_filelist_free(&fl);
            return 1;
        }
        if (fl.count == 0) {
            fprintf(stderr, "Error: No files found.\n");
            zupt_filelist_free(&fl); return 1;
        }

        banner();

        /* Password strength warning */
        if (opts.encrypt && opts.password[0]) {
            size_t pwlen = strlen(opts.password);
            int has_upper=0, has_lower=0, has_digit=0, has_special=0;
            for (size_t pi=0; pi<pwlen; pi++) {
                unsigned char ch = (unsigned char)opts.password[pi];
                if (ch>='A' && ch<='Z') has_upper=1;
                else if (ch>='a' && ch<='z') has_lower=1;
                else if (ch>='0' && ch<='9') has_digit=1;
                else has_special=1;
            }
            int classes = has_upper + has_lower + has_digit + has_special;
            if (pwlen < 8)
                fprintf(stderr, "  WARNING: Password is very short (%zu chars). Use 12+ chars for security.\n", pwlen);
            else if (pwlen < 12 && classes < 3)
                fprintf(stderr, "  WARNING: Weak password. Use 12+ chars with mixed case, digits, and symbols.\n");
        }

        /* Resolve thread count */
        opts.threads = zupt_resolve_threads(opts.threads);
        if (opts.solid && opts.threads > 1) {
            fprintf(stderr, "  Note: solid mode is single-threaded (cross-file LZ context)\n");
            opts.threads = 1;
        }

        /* Resolve AUTO codec based on hardware detection */
        if (opts.codec_id == ZUPT_CODEC_AUTO)
            opts.codec_id = zupt_resolve_auto_codec();

        fprintf(stderr, "  Collected %d file(s) for compression%s\n", fl.count,
                opts.solid ? " (SOLID MODE)" : "");
        if (opts.threads > 1)
            fprintf(stderr, "  Threads: %d\n", opts.threads);
        if (opts.encrypt) fprintf(stderr, "  Encryption: ENABLED\n");
        fprintf(stderr, "\n");

        zupt_error_t err;
        if (opts.solid) {
            err = zupt_compress_solid(output,
                (const char**)fl.arc_paths, (const char**)fl.paths, fl.count, &opts);
        } else {
            err = zupt_compress_files(output,
                (const char**)fl.arc_paths, (const char**)fl.paths, fl.count, &opts);
        }
        zupt_filelist_free(&fl);
        zupt_secure_wipe(opts.password, sizeof(opts.password));
        return err==ZUPT_OK ? 0 : 1;
    }

    /* ─── extract ─── */
    if (streq(cmd,"extract")||streq(cmd,"x")) {
        zupt_options_t opts; zupt_default_options(&opts);
        const char *outdir = NULL;
        const char *archive = NULL;
        /* POSIX-friendly: accept options before OR after the positional
         * archive argument. Scan all argv from index 2; pick first
         * non-option as archive, parse all options regardless of order. */
        int ai = 2;
        while (ai < argc) {
            if (!isopt(argv[ai])) {
                if (!archive) { archive = argv[ai]; ai++; continue; }
                fprintf(stderr, "Error: unexpected extra argument '%s'\n", argv[ai]); return 1;
            }
            int password_source = parse_password_source(
                argc, argv, &ai, &opts, 0);
            if (password_source < 0) return 1;
            if (password_source > 0) { ai++; continue; }
            if ((streq(argv[ai],"-o")||streq(argv[ai],"--output"))&&ai+1<argc)
                outdir = argv[++ai];
            else if (streq(argv[ai],"-p")||streq(argv[ai],"--password")) {
                opts.encrypt=1;
                if (ai+1<argc && !isopt(argv[ai+1])) strncpy(opts.password,argv[++ai],sizeof(opts.password)-1);
                else if (!prompt_password("Password: ", opts.password,
                                          sizeof(opts.password))) return 1;
            } else if (streq(argv[ai],"--allow-legacy-no-ait")) {
                zupt_internal_allow_legacy_no_ait(&opts);
            } else if (streq(argv[ai],"-v")||streq(argv[ai],"--verbose")) zupt_internal_set_verbose(&opts);
            else if ((streq(argv[ai],"-t")||streq(argv[ai],"--threads"))&&ai+1<argc) {
                opts.threads=atoi(argv[++ai]);
                if(opts.threads<0)opts.threads=0;
                if(opts.threads>ZUPT_MAX_THREADS)opts.threads=ZUPT_MAX_THREADS;
            }
            else if (streq(argv[ai],"--pq-box")&&ai+1<argc) {
                opts.pq_mode=1; opts.box_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq-sdk")&&ai+1<argc) {
                opts.pq_mode=1; opts.sdk_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq-only")&&ai+1<argc) {
                opts.pqonly_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq")&&ai+1<argc) {
                opts.pq_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            }
            else { fprintf(stderr,"Unknown option '%s'\n",argv[ai]); return 1; }
            ai++;
        }
        if (!archive) { fprintf(stderr,"Error: extract requires <archive.zupt>\n"); return 1; }
        banner();
        zupt_error_t err = zupt_extract_archive(archive, outdir, &opts);
        zupt_secure_wipe(opts.password, sizeof(opts.password));
        return err==ZUPT_OK ? 0 : 1;
    }

    /* ─── list ─── */
    if (streq(cmd,"list")||streq(cmd,"l")) {
        zupt_options_t opts; zupt_default_options(&opts);
        const char *archive = NULL;
        int ai = 2;
        while (ai < argc) {
            if (!isopt(argv[ai])) {
                if (!archive) { archive = argv[ai]; ai++; continue; }
                fprintf(stderr, "Error: unexpected extra argument '%s'\n", argv[ai]); return 1;
            }
            int password_source = parse_password_source(
                argc, argv, &ai, &opts, 0);
            if (password_source < 0) return 1;
            if (password_source > 0) { ai++; continue; }
            if (streq(argv[ai],"--allow-legacy-no-ait")) zupt_internal_allow_legacy_no_ait(&opts);
            else if (streq(argv[ai],"-v")||streq(argv[ai],"--verbose")) zupt_internal_set_verbose(&opts);
            else if (streq(argv[ai],"-p")||streq(argv[ai],"--password")) {
                opts.encrypt=1;
                if (ai+1<argc && !isopt(argv[ai+1])) strncpy(opts.password,argv[++ai],sizeof(opts.password)-1);
                else if (!prompt_password("Password: ", opts.password,
                                          sizeof(opts.password))) return 1;
            }
            else if (streq(argv[ai],"--pq-box")&&ai+1<argc) {
                opts.pq_mode=1; opts.box_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq-sdk")&&ai+1<argc) {
                opts.pq_mode=1; opts.sdk_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq-only")&&ai+1<argc) {
                opts.pqonly_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq")&&ai+1<argc) {
                opts.pq_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            }
            else { fprintf(stderr,"Unknown option '%s'\n",argv[ai]); return 1; }
            ai++;
        }
        if (!archive) { fprintf(stderr,"Error: list requires <archive.zupt>\n"); return 1; }
        zupt_error_t err = zupt_list_archive(archive, &opts);
        zupt_secure_wipe(opts.password, sizeof(opts.password));
        return err==ZUPT_OK ? 0 : 1;
    }

    /* ─── test ─── */
    if (streq(cmd,"test")||streq(cmd,"t")) {
        zupt_options_t opts; zupt_default_options(&opts);
        const char *archive = NULL;
        int ai = 2;
        while (ai < argc) {
            if (!isopt(argv[ai])) {
                if (!archive) { archive = argv[ai]; ai++; continue; }
                fprintf(stderr, "Error: unexpected extra argument '%s'\n", argv[ai]); return 1;
            }
            int password_source = parse_password_source(
                argc, argv, &ai, &opts, 0);
            if (password_source < 0) return 1;
            if (password_source > 0) { ai++; continue; }
            if (streq(argv[ai],"--allow-legacy-no-ait")) zupt_internal_allow_legacy_no_ait(&opts);
            else if (streq(argv[ai],"-v")||streq(argv[ai],"--verbose")) zupt_internal_set_verbose(&opts);
            else if (streq(argv[ai],"-p")||streq(argv[ai],"--password")) {
                opts.encrypt=1;
                if (ai+1<argc && !isopt(argv[ai+1])) strncpy(opts.password,argv[++ai],sizeof(opts.password)-1);
                else if (!prompt_password("Password: ", opts.password,
                                          sizeof(opts.password))) return 1;
            }
            else if (streq(argv[ai],"--pq-box")&&ai+1<argc) {
                opts.pq_mode=1; opts.box_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq-sdk")&&ai+1<argc) {
                opts.pq_mode=1; opts.sdk_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq-only")&&ai+1<argc) {
                opts.pqonly_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq")&&ai+1<argc) {
                opts.pq_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            }
            else { fprintf(stderr,"Unknown option '%s'\n",argv[ai]); return 1; }
            ai++;
        }
        if (!archive) { fprintf(stderr,"Error: test requires <archive.zupt>\n"); return 1; }
        banner();
        zupt_error_t err = zupt_test_archive(archive, &opts);
        zupt_secure_wipe(opts.password, sizeof(opts.password));
        return err==ZUPT_OK ? 0 : 1;
    }

    /* ─── bench ─── */
    if (streq(cmd,"bench")||streq(cmd,"b")) {
        int ai = 2;
        int compare_mode = 0;
        if (ai < argc && streq(argv[ai], "--compare")) { compare_mode = 1; ai++; }

        if (!compare_mode && ai >= argc) { fprintf(stderr, "Error: bench requires <files/dirs...> or --compare\n"); return 1; }

        /* Every benchmark artifact lives under one private, unpredictable
         * directory.  No predictable /tmp leaf is ever opened or truncated. */
        char bench_root[ZUPT_MAX_PATH] = {0};
        char gen_dir[ZUPT_MAX_PATH] = {0};
        if (compare_mode && ai >= argc) {
            if (!zupt_create_private_temp_directory(
                    bench_root, sizeof(bench_root)) ||
                !zupt_join_temp_path(gen_dir, sizeof(gen_dir), bench_root,
                                     "corpus") ||
                !zupt_write_benchmark_corpus(gen_dir)) {
                fprintf(stderr,
                        "Error: cannot create private benchmark corpus.\n");
                zupt_remove_temp_tree(bench_root);
                return 1;
            }
            /* Use gen_dir as the input path — need a writable argv slot */
            static char gen_arg[ZUPT_MAX_PATH];
            strncpy(gen_arg, gen_dir, sizeof(gen_arg)-1);
            gen_arg[sizeof(gen_arg)-1] = '\0';
            argv[argc] = gen_arg;
            ai = argc; argc++;
        }

        zupt_filelist_t fl; zupt_filelist_init(&fl);
        for (int i = ai; i < argc; i++)
            zupt_collect_files(&fl, argv[i], argv[i]);
        if (zupt_internal_filelist_failed(&fl)) {
            fprintf(stderr, "Input collection was incomplete.\n");
            zupt_filelist_free(&fl);
            zupt_remove_temp_tree(bench_root);
            return 1;
        }
        if (fl.count == 0) {
            fprintf(stderr, "No files found.\n");
            zupt_filelist_free(&fl);
            zupt_remove_temp_tree(bench_root);
            return 1;
        }
        if (bench_root[0] == '\0' &&
            !zupt_create_private_temp_directory(
                bench_root, sizeof(bench_root))) {
            fprintf(stderr,
                    "Error: cannot create private benchmark workspace.\n");
            zupt_filelist_free(&fl);
            return 1;
        }

        uint64_t total_in = 0;
        for (int i = 0; i < fl.count; i++) {
            FILE *tf = zupt_fopen_path(fl.paths[i], "rb");
            if (tf) { fseek(tf, 0, SEEK_END); total_in += (uint64_t)ftell(tf); fclose(tf); }
        }
        char isz[32]; zupt_format_size(total_in, isz, sizeof(isz));
        banner();

        if (compare_mode) {
            fprintf(stderr, "  Codec Comparison — %d file(s), %s\n\n", fl.count, isz);
            fprintf(stderr, "  %-20s %12s %12s %10s\n", "Codec", "Compress", "Decompress", "Ratio");
            fprintf(stderr, "  ────────────────────────────────────────────────────────────\n");

            char tmp_path[ZUPT_MAX_PATH + 64];
            char tmp_out[ZUPT_MAX_PATH + 64];
            if (!zupt_join_temp_path(tmp_path, sizeof(tmp_path), bench_root,
                                     "comparison.zupt") ||
                !zupt_join_temp_path(tmp_out, sizeof(tmp_out), bench_root,
                                     "extracted")) {
                fprintf(stderr, "Error: benchmark temporary path is too long.\n");
                zupt_filelist_free(&fl);
                zupt_remove_temp_tree(bench_root);
                return 1;
            }

            struct { const char *name; uint16_t codec; int level; } codecs[] = {
                {"VaptVupt UF",  ZUPT_CODEC_VAPTVUPT, 1},
                {"VaptVupt BAL", ZUPT_CODEC_VAPTVUPT, 5},
                {"VaptVupt EXT", ZUPT_CODEC_VAPTVUPT, 9},
                {"ZUPT-LZHP",    ZUPT_CODEC_ZUPT_LZHP,7},
                {"ZUPT-LZ",      ZUPT_CODEC_ZUPT_LZ,  5},
            };
            int ncodecs = (int)(sizeof(codecs)/sizeof(codecs[0]));

            for (int ci = 0; ci < ncodecs; ci++) {
                zupt_options_t opts; zupt_default_options(&opts);
                opts.codec_id = codecs[ci].codec; opts.level = codecs[ci].level; opts.quiet = 1;

                double t0 = zupt_monotonic_seconds();
                zupt_error_t cerr = zupt_compress_files(tmp_path,
                    (const char**)fl.arc_paths, (const char**)fl.paths, fl.count, &opts);
                double csec = zupt_monotonic_seconds() - t0;
                if (csec < 0.001) csec = 0.001;

                if (cerr != ZUPT_OK) { fprintf(stderr, "  %-20s  FAILED\n", codecs[ci].name); continue; }

                FILE *zf = zupt_fopen_path(tmp_path, "rb"); uint64_t zsize = 0;
                if (zf) { fseek(zf,0,SEEK_END); zsize=(uint64_t)ftell(zf); fclose(zf); }

                zupt_options_t dopts; zupt_default_options(&dopts); dopts.quiet = 1;
                t0 = zupt_monotonic_seconds();
                zupt_error_t derr =
                    zupt_extract_archive(tmp_path, tmp_out, &dopts);
                double dsec = zupt_monotonic_seconds() - t0;
                if (dsec < 0.001) dsec = 0.001;

                if (derr != ZUPT_OK) {
                    fprintf(stderr, "  %-20s  EXTRACT FAILED\n",
                            codecs[ci].name);
                    zupt_remove_temp_tree(tmp_out);
                    remove(tmp_path);
                    continue;
                }

                fprintf(stderr, "  %-20s %9.1f MB/s %9.1f MB/s %8.2f:1\n",
                    codecs[ci].name, (double)total_in/csec/1048576.0,
                    (double)total_in/dsec/1048576.0,
                    total_in>0&&zsize>0?(double)total_in/(double)zsize:1.0);

                if (zupt_remove_temp_tree(tmp_out) != 0)
                    fprintf(stderr,
                            "Warning: could not remove benchmark extraction tree.\n");
                remove(tmp_path);
            }

            /* External tools */
            fprintf(stderr, "  ────────────────────────────────────────────────────────────\n");
            char concat[ZUPT_MAX_PATH + 64];
            if (!zupt_join_temp_path(concat, sizeof(concat), bench_root,
                                     "concatenated-input")) {
                fprintf(stderr, "Error: benchmark temporary path is too long.\n");
                zupt_filelist_free(&fl);
                zupt_remove_temp_tree(bench_root);
                return 1;
            }
            FILE *cf = zupt_fopen_path(concat, "wb");
            if (cf) {
                for (int i=0;i<fl.count;i++){FILE*inf=zupt_fopen_path(fl.paths[i],"rb");if(inf){uint8_t buf[65536];size_t n;while((n=fread(buf,1,sizeof(buf),inf))>0)fwrite(buf,1,n,cf);fclose(inf);}}
                fclose(cf);
            }
#ifndef _WIN32
            const char *exts[][3] = {
                {"gzip -6","gzip -6 -k -f","gzip -d -k -f"},
                {"lz4","lz4 -f","lz4 -d -f"},
                {"zstd -1","zstd -1 -f","zstd -d -f"},
                {"zstd -7","zstd -7 -f","zstd -d -f"},
                {NULL,NULL,NULL}
            };
            const char *ext_sfx[] = {".gz",".lz4",".zst",".zst"};
            for (int ti=0; exts[ti][0]; ti++) {
                char tn[32]; strncpy(tn,exts[ti][0],sizeof(tn)-1); char *sp=strchr(tn,' '); if(sp)*sp='\0';
                char wh[128]; snprintf(wh,sizeof(wh),"command -v %s >/dev/null 2>&1",tn);
                if (system(wh)!=0) continue;

                char co[ZUPT_MAX_PATH + 80]; snprintf(co,sizeof(co),"%s%s",concat,ext_sfx[ti]);
                remove(co);
                char ccmd[ZUPT_MAX_PATH + 160];
                snprintf(ccmd,sizeof(ccmd),"%s '%s' >/dev/null 2>&1",exts[ti][1],concat);
                double t0 = zupt_monotonic_seconds();
                if (system(ccmd)) { /* ignore */ }
                double csec = zupt_monotonic_seconds() - t0;
                if(csec<0.001)csec=0.001;
                FILE*ef=zupt_fopen_path(co,"rb"); uint64_t esz=0; if(ef){fseek(ef,0,SEEK_END);esz=(uint64_t)ftell(ef);fclose(ef);}

                char dcmd[ZUPT_MAX_PATH + 160];
                snprintf(dcmd,sizeof(dcmd),"%s '%s' >/dev/null 2>&1",exts[ti][2],co);
                t0 = zupt_monotonic_seconds();
                if (system(dcmd)) { /* ignore */ }
                double dsec = zupt_monotonic_seconds() - t0;
                if(dsec<0.001)dsec=0.001;

                fprintf(stderr, "  %-20s %9.1f MB/s %9.1f MB/s %8.2f:1\n",
                    exts[ti][0], (double)total_in/csec/1048576.0, (double)total_in/dsec/1048576.0,
                    total_in>0&&esz>0?(double)total_in/(double)esz:1.0);
                remove(co); char dec[ZUPT_MAX_PATH + 80]; snprintf(dec,sizeof(dec),"%s.dec",concat); remove(dec);
            }
#endif
            remove(concat);
            fprintf(stderr, "\n");
        } else {
            /* ═══ ORIGINAL PER-LEVEL BENCHMARK ═══ */
            fprintf(stderr, "  Benchmarking %d file(s), %s\n\n", fl.count, isz);
            fprintf(stderr, "  %-7s %12s %10s %10s %10s\n", "Level", "Compressed", "Ratio", "%", "Speed");
            fprintf(stderr, "  ─────────────────────────────────────────────────────────\n");

            char tmp_path[ZUPT_MAX_PATH + 64];
            if (!zupt_join_temp_path(tmp_path, sizeof(tmp_path), bench_root,
                                     "levels.zupt")) {
                fprintf(stderr, "Error: benchmark temporary path is too long.\n");
                zupt_filelist_free(&fl);
                zupt_remove_temp_tree(bench_root);
                return 1;
            }

            for (int lvl = 1; lvl <= 9; lvl++) {
                zupt_options_t opts; zupt_default_options(&opts);
                opts.level = lvl;
                opts.verbose = 0;
                opts.quiet = 1;

                time_t t0 = time(NULL);
                zupt_error_t err = zupt_compress_files(tmp_path,
                    (const char**)fl.arc_paths, (const char**)fl.paths, fl.count, &opts);
                time_t elapsed = time(NULL) - t0;
                if (elapsed < 1) elapsed = 1;

                if (err == ZUPT_OK) {
                    FILE *zf = zupt_fopen_path(tmp_path, "rb");
                    uint64_t zsize = 0;
                    if (zf) { fseek(zf, 0, SEEK_END); zsize = (uint64_t)ftell(zf); fclose(zf); }

                    char csz[32]; zupt_format_size(zsize, csz, sizeof(csz));
                    double ratio = total_in > 0 ? (double)total_in / (double)zsize : 1.0;
                    double pct = total_in > 0 ? (double)zsize / (double)total_in * 100.0 : 100.0;
                    double speed = (double)total_in / (double)elapsed / 1048576.0;

                    fprintf(stderr, "  %-7d %12s %9.2f:1 %9.1f%% %8.1f MB/s\n",
                            lvl, csz, ratio, pct, speed);
                } else {
                    fprintf(stderr, "  %-7d %12s\n", lvl, "FAILED");
                }
                remove(tmp_path);
            }
            fprintf(stderr, "\n");
        }

        zupt_filelist_free(&fl);
        if (zupt_remove_temp_tree(bench_root) != 0) {
            fprintf(stderr, "Error: could not remove private benchmark workspace.\n");
            return 1;
        }
        return 0;
    }

    /* ─── disk (backup/restore) ─── */
    if (streq(cmd,"disk")) {
        if (argc < 3) {
            fprintf(stderr, "Usage:\n");
            fprintf(stderr, "  zupt disk backup  [OPTIONS] <output.zupt> <device_or_file>\n");
            fprintf(stderr, "  zupt disk restore [OPTIONS] <archive.zupt> <target_device_or_file>\n");
            fprintf(stderr, "\nOptions:\n");
            fprintf(stderr, "  -l <1-9>          Compression level (default: 7)\n");
            fprintf(stderr, "  -b <SIZE>         Block size (default: 4MB for disks)\n");
            fprintf(stderr, "  -p [PW]           Password encryption\n");
            fprintf(stderr, "  --pq <keyfile>    Post-quantum encryption\n");
            fprintf(stderr, "  --vv              Force VaptVupt codec\n");
            fprintf(stderr, "  --lzhp            Force ZUPT-LZHP codec\n");
            fprintf(stderr, "  -t <N>            Thread count\n");
            fprintf(stderr, "  -v                Verbose\n");
            fprintf(stderr, "  --allow-legacy-no-ait  Restore a trusted old archive without AIT\n");
            fprintf(stderr, "\nExamples:\n");
            fprintf(stderr, "  zupt disk backup backup.zupt /dev/sda1\n");
            fprintf(stderr, "  zupt disk backup -p secret encrypted.zupt /dev/nvme0n1p2\n");
            fprintf(stderr, "  zupt disk backup --pq pub.key pq_backup.zupt disk.img\n");
            fprintf(stderr, "  zupt disk restore backup.zupt /dev/sda1\n");
            fprintf(stderr, "  zupt disk restore -p secret encrypted.zupt /dev/sda1\n");
            return 1;
        }

        const char *subcmd = argv[2];
        if (!streq(subcmd,"backup") && !streq(subcmd,"restore")) {
            fprintf(stderr, "Error: disk subcommand must be 'backup' or 'restore'\n");
            return 1;
        }

        zupt_options_t opts; zupt_default_options(&opts);
        int ai = 3;
        while (ai<argc && isopt(argv[ai])) {
            int password_source = parse_password_source(
                argc, argv, &ai, &opts, streq(subcmd, "backup"));
            if (password_source < 0) return 1;
            if (password_source > 0) { ai++; continue; }
            if ((streq(argv[ai],"-l")||streq(argv[ai],"--level"))&&ai+1<argc) {
                opts.level=atoi(argv[++ai]); if(opts.level<1)opts.level=1; if(opts.level>9)opts.level=9;
            } else if ((streq(argv[ai],"-b")||streq(argv[ai],"--block"))&&ai+1<argc) {
                opts.block_size=(uint32_t)atol(argv[++ai]);
                if(opts.block_size<ZUPT_MIN_BLOCK_SZ)opts.block_size=ZUPT_MIN_BLOCK_SZ;
                if(opts.block_size>ZUPT_MAX_BLOCK_SZ)opts.block_size=ZUPT_MAX_BLOCK_SZ;
            } else if (streq(argv[ai],"--vv")||streq(argv[ai],"--vaptvupt")) {
                opts.codec_id=ZUPT_CODEC_VAPTVUPT;
            } else if (streq(argv[ai],"--lzhp")) {
                opts.codec_id=ZUPT_CODEC_ZUPT_LZHP;
            } else if (streq(argv[ai],"-s")||streq(argv[ai],"--store")) {
                opts.codec_id=ZUPT_CODEC_STORE;
            } else if (streq(argv[ai],"-p")||streq(argv[ai],"--password")) {
                opts.encrypt=1;
                if (ai+1<argc && !isopt(argv[ai+1])) {
                    strncpy(opts.password, argv[++ai], sizeof(opts.password)-1);
                } else {
                    if (!prompt_password("Password: ", opts.password,
                                         sizeof(opts.password))) return 1;
                    if (streq(subcmd,"backup")) {
                        char confirm[256];
                        if (!prompt_password("Confirm:  ", confirm,
                                             sizeof(confirm))) {
                            zupt_secure_wipe(opts.password,
                                             sizeof(opts.password));
                            return 1;
                        }
                        if (strcmp(opts.password, confirm)!=0) {
                            zupt_secure_wipe(confirm, sizeof(confirm));
                            fprintf(stderr, "Error: Passwords do not match.\n"); return 1;
                        }
                        zupt_secure_wipe(confirm, sizeof(confirm));
                    }
                }
            } else if (streq(argv[ai],"-v")||streq(argv[ai],"--verbose")) {
                zupt_internal_set_verbose(&opts);
            } else if ((streq(argv[ai],"-t")||streq(argv[ai],"--threads"))&&ai+1<argc) {
                opts.threads=atoi(argv[++ai]);
            } else if (streq(argv[ai],"--pq-only")&&ai+1<argc) {
                opts.pqonly_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--pq")&&ai+1<argc) {
                opts.pq_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else if (streq(argv[ai],"--dedup")||streq(argv[ai],"-D")) {
                opts.dedup=1;
            } else if (streq(argv[ai],"--allow-legacy-no-ait")) {
                if (!streq(subcmd,"restore")) {
                    fprintf(stderr,
                            "Error: --allow-legacy-no-ait is valid only for disk restore.\n");
                    return 1;
                }
                zupt_internal_allow_legacy_no_ait(&opts);
            } else if ((streq(argv[ai],"-c")||streq(argv[ai],"--comment"))&&ai+1<argc) {
                /* v2.4.3: free-form archive comment. Encrypted along with
                 * data blocks when -p/--pq is also set. */
                ai++;
                strncpy(opts.comment, argv[ai], ZUPT_MAX_COMMENT_LEN - 1);
                opts.comment[ZUPT_MAX_COMMENT_LEN - 1] = '\0';
                opts.has_comment = 1;
            } else if (streq(argv[ai],"--comment-file")&&ai+1<argc) {
                ai++;
                FILE *cf = zupt_fopen_path(argv[ai], "rb");
                if (!cf) {
                    fprintf(stderr, "Error: --comment-file: cannot open '%s'\n", argv[ai]);
                    return 1;
                }
                size_t n = fread(opts.comment, 1, ZUPT_MAX_COMMENT_LEN - 1, cf);
                opts.comment[n] = '\0';
                while (n > 0 && (opts.comment[n-1] == '\n' || opts.comment[n-1] == '\r')) {
                    opts.comment[--n] = '\0';
                }
                opts.has_comment = (n > 0);
                fclose(cf);
            } else if (streq(argv[ai],"--kdf")&&ai+1<argc) {
                /* Argon2id is supplied only by the optional system SDK.
                 * Never silently downgrade an explicit request to PBKDF2. */
                ai++;
                if (streq(argv[ai],"pbkdf2")) {
                    opts.kdf_legacy_pbkdf2 = 1;
                } else if (streq(argv[ai],"argon2id") || streq(argv[ai],"argon2")) {
#ifdef ZUPT_WITH_SDK
                    opts.kdf_legacy_pbkdf2 = 0;
#else
                    fprintf(stderr,
                        "Error: --kdf argon2id requires a WITH_SDK=1 build with system libvuptsdk.\n");
                    return 1;
#endif
                } else {
                    fprintf(stderr, "Error: unsupported --kdf value '%s'.\n", argv[ai]);
                    return 1;
                }
            } else {
                fprintf(stderr,"Error: Unknown option '%s'\n",argv[ai]); return 1;
            }
            ai++;
        }

        if (argc - ai < 2) {
            fprintf(stderr, "Error: disk %s requires <archive> <device/file>\n", subcmd);
            return 1;
        }

        banner();

        if (streq(subcmd,"backup")) {
            const char *output = argv[ai];
            const char *source = argv[ai+1];
            fprintf(stderr, "  Full-Disk Backup\n");
            fprintf(stderr, "  ═══════════════════════════════════════\n\n");
            zupt_error_t err = zupt_disk_backup(output, source, &opts);
            zupt_secure_wipe(opts.password, sizeof(opts.password));
            return err == ZUPT_OK ? 0 : 1;
        } else {
            const char *archive = argv[ai];
            const char *target = argv[ai+1];
            fprintf(stderr, "  Full-Disk Restore\n");
            fprintf(stderr, "  ═══════════════════════════════════════\n\n");
            zupt_error_t err = zupt_disk_restore(archive, target, &opts);
            zupt_secure_wipe(opts.password, sizeof(opts.password));
            return err == ZUPT_OK ? 0 : 1;
        }
    }

    /* ─── keygen ─── */
    if (streq(cmd,"keygen")) {
        const char *outfile = NULL;
        const char *privfile = NULL;
        int export_pub = 0;
        int sdk_mode = 0;
        int box_mode = 0;
        int pqonly_mode = 0;
        int ai = 2;
        while (ai < argc && isopt(argv[ai])) {
            if ((streq(argv[ai],"-o")||streq(argv[ai],"--output")) && ai+1 < argc)
                outfile = argv[++ai];
            else if ((streq(argv[ai],"-k")||streq(argv[ai],"--key")) && ai+1 < argc)
                privfile = argv[++ai];
            else if (streq(argv[ai],"--pub"))
                export_pub = 1;
            else if (streq(argv[ai],"--sdk")||streq(argv[ai],"--pq-sdk"))
                sdk_mode = 1;
            else if (streq(argv[ai],"--box")||streq(argv[ai],"--pq-box"))
                box_mode = 1;
            else if (streq(argv[ai],"--pq-only")||streq(argv[ai],"--pqonly"))
                pqonly_mode = 1;
            else { fprintf(stderr, "Unknown option '%s'\n", argv[ai]); return 1; }
            ai++;
        }

        if (!outfile) {
            fprintf(stderr, "Error: keygen requires -o <output_file>\n");
            fprintf(stderr, "  zupt keygen -o keyfile.key           # Generate keypair\n");
            fprintf(stderr, "  zupt keygen --pub -o pub.key -k priv.key  # Export public key\n");
            return 1;
        }

        banner();
        if (export_pub) {
            if (!privfile) { fprintf(stderr, "Error: --pub requires -k <private_keyfile>\n"); return 1; }
            fprintf(stderr, "  Exporting public key from: %s\n", privfile);
            int erc = pqonly_mode ? zupt_pq_export_pubkey(privfile, outfile)
                                  : zupt_hybrid_export_pubkey(privfile, outfile);
            if (erc != 0) {
                fprintf(stderr, "Error: Failed to export public key%s.\n",
                        pqonly_mode ? "" : " (for full-PQ keys use: keygen --pub --pq-only)");
                return 1;
            }
            fprintf(stderr, "  Public key written to: %s\n", outfile);
        } else if (pqonly_mode) {
            fprintf(stderr, "  Generating ML-KEM-768 keypair (full post-quantum, no X25519)...\n");
            if (zupt_pq_keygen(outfile) != 0) {
                fprintf(stderr, "Error: full-PQ key generation failed.\n"); return 1;
            }
            fprintf(stderr, "  Private key written to: %s\n", outfile);
            fprintf(stderr, "  SECURITY: Keep this file secret. Back it up securely.\n");
            fprintf(stderr, "  To export public key: zupt keygen --pub --pq-only -o pub.key -k %s\n", outfile);
        } else if (box_mode) {
            fprintf(stderr, "  Generating ML-KEM-768 + X25519 keypair (pq-box format)...\n");
            char pubfile[512];
            snprintf(pubfile, sizeof(pubfile), "%s.pub", outfile);
            if (zupt_pqbox_keygen(outfile, pubfile) != 0) {
                fprintf(stderr, "Error: pq-box key generation failed.\n"); return 1;
            }
            fprintf(stderr, "  Private key:  %s\n", outfile);
            fprintf(stderr, "  Public key:   %s\n", pubfile);
            fprintf(stderr, "  SECURITY: Keep the private key file secret.\n");
        } else if (sdk_mode) {
            fprintf(stderr, "  Generating ML-KEM-768 + X25519 keypair (SDK-v2 format)...\n");
            char pubfile[512];
            snprintf(pubfile, sizeof(pubfile), "%s.pub", outfile);
            if (zupt_sdk_hybrid_keygen(outfile, pubfile) != 0) {
                fprintf(stderr,
                    "Error: SDK-v2 key generation is unavailable in this build.\n"
                    "       --pq-sdk needs libvuptsdk, which is not part of the source-only\n"
                    "       build. For post-quantum keys use one of the native modes:\n"
                    "         zupt keygen -o key            # hybrid ML-KEM-768 + X25519 (--pq)\n"
                    "         zupt keygen --pq-only -o key  # full PQ, ML-KEM-768 only (--pq-only)\n"
                    "       (Rebuild upstream with 'make WITH_SDK=1' to enable --pq-sdk.)\n");
                return 1;
            }
            fprintf(stderr, "  Private key:  %s\n", outfile);
            fprintf(stderr, "  Public key:   %s\n", pubfile);
            fprintf(stderr, "  SECURITY: Keep the private key file secret.\n");
        } else {
            fprintf(stderr, "  Generating ML-KEM-768 + X25519 keypair...\n");
            if (zupt_hybrid_keygen(outfile) != 0) {
                fprintf(stderr, "Error: Key generation failed.\n"); return 1;
            }
            fprintf(stderr, "  Private key written to: %s\n", outfile);
            fprintf(stderr, "  SECURITY: Keep this file secret. Back it up securely.\n");
            fprintf(stderr, "  To export public key: zupt keygen --pub -o pub.key -k %s\n", outfile);
        }
        return 0;
    }

    fprintf(stderr, "Unknown command '%s'. Run 'zupt help'.\n", cmd);
    return 1;
}

#ifdef _WIN32
int wmain(int argc, wchar_t **wide_argv);

int wmain(int argc, wchar_t **wide_argv) {
    char **utf8_argv = (char **)calloc((size_t)argc + 1, sizeof(char *));
    if (!utf8_argv) return 1;
    for (int i = 0; i < argc; i++) {
        utf8_argv[i] = zupt_win_wide_to_utf8_alloc(wide_argv[i]);
        if (!utf8_argv[i]) {
            for (int j = 0; j < i; j++) {
                zupt_secure_wipe(utf8_argv[j], strlen(utf8_argv[j]));
                free(utf8_argv[j]);
            }
            free(utf8_argv);
            fprintf(stderr, "Error: command line is not valid Unicode.\n");
            return 1;
        }
    }
    int result = zupt_cli_main(argc, utf8_argv);
    for (int i = 0; i < argc; i++) {
        zupt_secure_wipe(utf8_argv[i], strlen(utf8_argv[i]));
        free(utf8_argv[i]);
    }
    free(utf8_argv);
    return result;
}
#else
int main(int argc, char **argv) {
    return zupt_cli_main(argc, argv);
}
#endif
