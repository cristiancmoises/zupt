/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Run the real disk-size/capacity helpers against both Linux ioctl ABIs.
 * Only metadata and ioctl are injected; no device is opened or queried.
 */
#ifdef NDEBUG
#error "disk ioctl ABI regression requires assertions"
#endif
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>

#if TEST_IOCTL_INT
typedef int test_request_t;
#else
typedef unsigned long test_request_t;
#endif

static int expected_descriptor;
static int pretend_block;
static int stat_failure;
static int ioctl_result;
static unsigned int ioctl_calls;
static uint64_t ioctl_bytes;

static int test_fstat(int descriptor, struct stat *info) {
    assert(descriptor == expected_descriptor);
    if (stat_failure) {
        errno = EIO;
        return -1;
    }
    int result = fstat(descriptor, info);
    if (result == 0 && pretend_block) info->st_mode = S_IFBLK;
    return result;
}

static int test_ioctl(int descriptor, test_request_t request, ...) {
    assert(descriptor == expected_descriptor);
#if TEST_IOCTL_INT
    /* Linux consumes the unsigned 32-bit command, even for the int ABI. */
    assert((unsigned int)request == (unsigned int)BLKGETSIZE64);
#else
    /* The unsigned-long ABI must retain the original UAPI macro value. */
    assert(request == BLKGETSIZE64);
#endif
    va_list args;
    va_start(args, request);
    uint64_t *bytes = va_arg(args, uint64_t *);
    va_end(args);
    assert(bytes != NULL && *bytes == 0);
    *bytes = ioctl_bytes;
    ioctl_calls++;
    if (ioctl_result != 0) errno = EIO;
    return ioctl_result;
}

#define fstat test_fstat
#define ioctl test_ioctl
#include "../src/zupt_disk.c"
#undef ioctl
#undef fstat

int main(void) {
    FILE *stream = tmpfile();
    assert(stream != NULL);
    expected_descriptor = fileno(stream);
    assert(expected_descriptor >= 0);
    assert(fwrite("capacity", 1, 8, stream) == 8);
    assert(fflush(stream) == 0);
    assert(fseek(stream, 3, SEEK_SET) == 0);

    /* Ordinary file sizing neither queries ioctl nor moves the stream. */
    assert(get_device_size(stream) == 8);
    assert(ioctl_calls == 0 && ftell(stream) == 3);

    struct stat block_info;
    assert(fstat(expected_descriptor, &block_info) == 0);
    block_info.st_mode = S_IFBLK;
    pretend_block = 1;

    /* A size above 32 bits reaches both callers without truncation. */
    ioctl_bytes = UINT64_C(5368709243);
    assert(get_device_size(stream) == INT64_C(5368709243));
    assert(ioctl_calls == 1 && ftell(stream) == 3);
    uint64_t capacity = 37;
    assert(disk_restore_target_capacity(expected_descriptor,
                                        &block_info, &capacity) == 1);
    assert(capacity == UINT64_C(5368709243) && ioctl_calls == 2);

    /* Even a failing ioctl that writes its buffer cannot publish a size. */
    ioctl_result = -1;
    ioctl_bytes = 4096;
    assert(get_device_size(stream) == -1);
    assert(ioctl_calls == 3 && ftell(stream) == 3);
    capacity = 37;
    assert(disk_restore_target_capacity(expected_descriptor,
                                        &block_info, &capacity) == 0);
    assert(capacity == 37 && ioctl_calls == 4 && errno == ENOTSUP);

    /* Backup retains empty-size semantics; restore rejects zero capacity. */
    ioctl_result = 0;
    ioctl_bytes = 0;
    assert(get_device_size(stream) == 0);
    assert(ioctl_calls == 5 && ftell(stream) == 3);
    assert(disk_restore_target_capacity(expected_descriptor,
                                        &block_info, &capacity) == 0);
    assert(capacity == 37 && ioctl_calls == 6 && errno == ENOTSUP);

    /* Metadata errors and unknown device kinds fail without issuing ioctl. */
    stat_failure = 1;
    assert(get_device_size(stream) == -1);
    assert(ioctl_calls == 6 && ftell(stream) == 3);
    block_info.st_mode = S_IFCHR;
    assert(disk_restore_target_capacity(expected_descriptor,
                                        &block_info, &capacity) == 0);
    assert(capacity == 37 && ioctl_calls == 6 && errno == ENOTSUP);
    assert(disk_restore_target_capacity(expected_descriptor,
                                        NULL, &capacity) == 0);
    assert(capacity == 37 && ioctl_calls == 6 && errno == EINVAL);
    assert(disk_restore_target_capacity(expected_descriptor,
                                        &block_info, NULL) == 0);
    assert(ioctl_calls == 6 && errno == EINVAL);
    assert(fclose(stream) == 0);

    puts("PASS: disk ioctl request ABI, size/capacity and failure guards");
    return 0;
}
