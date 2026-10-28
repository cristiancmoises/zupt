/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Exercise Huffman allocation failures against the actual implementation.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/vv_huffman.h"

#define MAX_TRACKED_ALLOCATIONS 8

static void *tracked[MAX_TRACKED_ALLOCATIONS];
static size_t allocation_calls;
static size_t live_allocations;
static size_t fail_at;
static int failure_triggered;

static void track_pointer(void *pointer)
{
    if (!pointer)
        return;
    for (size_t i = 0; i < MAX_TRACKED_ALLOCATIONS; i++) {
        if (!tracked[i]) {
            tracked[i] = pointer;
            live_allocations++;
            return;
        }
    }
    abort();
}

static void *injected_malloc(size_t size)
{
    allocation_calls++;
    if (allocation_calls == fail_at) {
        failure_triggered = 1;
        return NULL;
    }
    void *pointer = malloc(size);
    track_pointer(pointer);
    return pointer;
}

static void *injected_calloc(size_t count, size_t size)
{
    allocation_calls++;
    if (allocation_calls == fail_at) {
        failure_triggered = 1;
        return NULL;
    }
    void *pointer = calloc(count, size);
    track_pointer(pointer);
    return pointer;
}

static void injected_free(void *pointer)
{
    if (!pointer)
        return;
    for (size_t i = 0; i < MAX_TRACKED_ALLOCATIONS; i++) {
        if (tracked[i] == pointer) {
            tracked[i] = NULL;
            live_allocations--;
            free(pointer);
            return;
        }
    }
    abort();
}

#define malloc injected_malloc
#define calloc injected_calloc
#define free injected_free
#include "../src/vv_huffman.c"
#undef free
#undef calloc
#undef malloc

typedef vvh_error_t (*encode_fn)(const uint8_t *, size_t, uint8_t *,
                                 size_t, size_t *);
typedef vvh_error_t (*decode_fn)(const uint8_t *, size_t, uint8_t *,
                                 size_t, size_t, size_t *);

static int reset_allocator(size_t failure)
{
    if (live_allocations != 0)
        return 0;
    memset(tracked, 0, sizeof(tracked));
    allocation_calls = 0;
    fail_at = failure;
    failure_triggered = 0;
    return 1;
}

static int check_failure(const char *name, encode_fn encode,
                         size_t ordinal, const uint8_t *input,
                         size_t input_size)
{
    uint8_t encoded[8192];
    size_t encoded_size = 0;

    if (!reset_allocator(ordinal)) {
        fprintf(stderr, "FAIL: %s allocation %zu starts with live storage\n",
                name, ordinal);
        return 0;
    }

    vvh_error_t result = encode(input, input_size, encoded,
                                sizeof(encoded), &encoded_size);
    if (result != VVH_ERR_NOMEM || !failure_triggered ||
        live_allocations != 0) {
        fprintf(stderr,
                "FAIL: %s allocation %zu result=%d triggered=%d calls=%zu live=%zu\n",
                name, ordinal, (int)result, failure_triggered,
                allocation_calls, live_allocations);
        return 0;
    }
    return 1;
}

static int check_success(const char *name, encode_fn encode, decode_fn decode,
                         const uint8_t *input, size_t input_size)
{
    uint8_t encoded[8192];
    uint8_t decoded[4096];
    size_t encoded_size = 0;
    size_t consumed = 0;

    if (!reset_allocator(0))
        return 0;
    vvh_error_t result = encode(input, input_size, encoded,
                                sizeof(encoded), &encoded_size);
    if (result != VVH_OK || encoded_size == 0 || encoded_size >= input_size ||
        live_allocations != 0) {
        fprintf(stderr,
                "FAIL: %s successful encode result=%d bytes=%zu live=%zu\n",
                name, (int)result, encoded_size, live_allocations);
        return 0;
    }

    if (!reset_allocator(0))
        return 0;
    result = decode(encoded, encoded_size, decoded, sizeof(decoded),
                    input_size, &consumed);
    if (result != VVH_OK || consumed > encoded_size ||
        memcmp(input, decoded, input_size) != 0 || live_allocations != 0) {
        fprintf(stderr,
                "FAIL: %s successful decode result=%d consumed=%zu live=%zu\n",
                name, (int)result, consumed, live_allocations);
        return 0;
    }
    return 1;
}

static int check_truncated_decode_before_allocation(void)
{
    uint8_t input[512];
    uint8_t encoded[2048];
    uint8_t decoded[sizeof(input)];
    uint8_t lengths[VVH_SYMBOLS];
    size_t encoded_size = 0;
    size_t consumed = 0;

    for (size_t i = 0; i < sizeof(input); i++)
        input[i] = (uint8_t)(i & 3U);

    if (!reset_allocator(0) ||
        vvh_encode(input, sizeof(input), encoded, sizeof(encoded),
                   &encoded_size) != VVH_OK ||
        live_allocations != 0) {
        fprintf(stderr, "FAIL: cannot prepare Huffman truncation fixture\n");
        return 0;
    }

    size_t header_size = read_header(encoded, encoded_size, lengths);
    if (header_size == 0 || header_size >= encoded_size) {
        fprintf(stderr, "FAIL: invalid Huffman truncation fixture header\n");
        return 0;
    }

    if (!reset_allocator(0))
        return 0;
    vvh_error_t result = vvh_decode(encoded, header_size, decoded,
                                    sizeof(decoded), sizeof(input), &consumed);
    if (result != VVH_ERR_CORRUPT || allocation_calls != 0 ||
        live_allocations != 0) {
        fprintf(stderr,
                "FAIL: truncated Huffman decode result=%d calls=%zu live=%zu\n",
                (int)result, allocation_calls, live_allocations);
        return 0;
    }
    return 1;
}

int main(void)
{
    uint8_t input[4096];
    int failures_ok = 1;

    for (size_t i = 0; i < sizeof(input); i++)
        input[i] = (uint8_t)((i * 37U + i / 7U) & 15U);

    for (size_t ordinal = 1; ordinal <= 3; ordinal++) {
        if (!check_failure("Huffman", vvh_encode, ordinal,
                           input, sizeof(input)))
            failures_ok = 0;
        if (!check_failure("Huffman4", vvh_encode4, ordinal,
                           input, sizeof(input)))
            failures_ok = 0;
    }
    if (!failures_ok)
        return 1;

    if (!check_success("Huffman", vvh_encode, vvh_decode,
                       input, sizeof(input)) ||
        !check_success("Huffman4", vvh_encode4, vvh_decode4,
                       input, sizeof(input)))
        return 1;

    if (!check_truncated_decode_before_allocation())
        return 1;

    puts("PASS: Huffman encoders propagate allocation failures (6 cases)");
    puts("PASS: Huffman successful encode/decode releases all owned storage");
    puts("PASS: truncated Huffman bitstreams are rejected before table allocation");
    return 0;
}
