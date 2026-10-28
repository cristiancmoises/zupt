/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Exercise ANS4 allocation failures against the actual implementation.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TRACKED_ALLOCATIONS 16

static void *tracked[MAX_TRACKED_ALLOCATIONS];
static size_t allocation_calls;
static size_t live_allocations;
static size_t fail_at;

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
    if (allocation_calls == fail_at)
        return NULL;
    void *pointer = malloc(size);
    track_pointer(pointer);
    return pointer;
}

static void *injected_calloc(size_t count, size_t size)
{
    allocation_calls++;
    if (allocation_calls == fail_at)
        return NULL;
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
#include "../src/vv_ans.c"
#undef free
#undef calloc
#undef malloc

static int reset_allocator(size_t failure)
{
    if (live_allocations != 0)
        return 0;
    memset(tracked, 0, sizeof(tracked));
    allocation_calls = 0;
    fail_at = failure;
    return 1;
}

static int check_failure(size_t ordinal, const uint8_t *input, size_t input_size)
{
    uint8_t encoded[8192];
    size_t encoded_size = 0;
    if (!reset_allocator(ordinal)) {
        fprintf(stderr, "FAIL: allocation %zu starts with live storage\n", ordinal);
        return 0;
    }

    vva_error_t result = vva_encode4(input, input_size, encoded,
                                     sizeof(encoded), &encoded_size);
    if (result != VVA_ERR_NOMEM || allocation_calls != ordinal ||
        live_allocations != 0) {
        fprintf(stderr,
                "FAIL: allocation %zu result=%d calls=%zu live=%zu\n",
                ordinal, (int)result, allocation_calls, live_allocations);
        return 0;
    }
    return 1;
}

static int check_success(const uint8_t *input, size_t input_size)
{
    uint8_t encoded[8192];
    uint8_t decoded[4096];
    size_t encoded_size = 0;
    size_t consumed = 0;

    if (!reset_allocator(0))
        return 0;
    vva_error_t result = vva_encode4(input, input_size, encoded,
                                     sizeof(encoded), &encoded_size);
    if (result != VVA_OK || encoded_size == 0 || encoded_size >= input_size ||
        live_allocations != 0) {
        fprintf(stderr, "FAIL: successful encode result=%d bytes=%zu live=%zu\n",
                (int)result, encoded_size, live_allocations);
        return 0;
    }

    if (!reset_allocator(0))
        return 0;
    result = vva_decode4(encoded, encoded_size, decoded, sizeof(decoded),
                         input_size, &consumed);
    if (result != VVA_OK || consumed > encoded_size ||
        memcmp(input, decoded, input_size) != 0 || live_allocations != 0) {
        fprintf(stderr,
                "FAIL: successful decode result=%d consumed=%zu live=%zu\n",
                (int)result, consumed, live_allocations);
        return 0;
    }
    return 1;
}

static int check_invalid_decode_arguments(void)
{
    uint8_t source[8] = {0};
    uint8_t output[8] = {0};
    size_t consumed = 0;

    if (vva_decode(NULL, sizeof(source), output, sizeof(output), 1,
                   &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode(source, sizeof(source), NULL, sizeof(output), 1,
                   &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode(source, sizeof(source), output, sizeof(output), 1,
                   NULL) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode(source, sizeof(source), output, 0, 1,
                   &consumed) != VVA_ERR_OVERFLOW)
        return 0;
    if (vva_decode4(NULL, sizeof(source), output, sizeof(output), 1,
                    &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode4(source, sizeof(source), NULL, sizeof(output), 1,
                    &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode4(source, sizeof(source), output, sizeof(output), 1,
                    NULL) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode4(source, sizeof(source), output, 0, 1,
                    &consumed) != VVA_ERR_OVERFLOW)
        return 0;
    consumed = SIZE_MAX;
    if (vva_decode_ctx(NULL, 0, output, sizeof(output), 1,
                       &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode_ctx(NULL, sizeof(source), output, sizeof(output), 1,
                       &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode_ctx(source, sizeof(source), NULL, sizeof(output), 1,
                       &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode_ctx(source, sizeof(source), output, sizeof(output), 1,
                       NULL) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode_ctx(source, sizeof(source), output, 0, 1,
                       &consumed) != VVA_ERR_OVERFLOW)
        return 0;
    if (vva_decode_ctx(source, sizeof(source), NULL, 0, 1,
                       &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode_ctx(NULL, sizeof(source), output, sizeof(output), 0,
                       &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode_ctx(source, sizeof(source), NULL, sizeof(output), 0,
                       &consumed) != VVA_ERR_PARAM)
        return 0;
    if (vva_decode_ctx(NULL, 0, NULL, 0, 0, NULL) != VVA_ERR_PARAM)
        return 0;
    if (consumed != SIZE_MAX)
        return 0;
    for (size_t i = 0; i < sizeof(output); i++)
        if (output[i] != 0)
            return 0;
    if (vva_decode_ctx(NULL, 0, NULL, 0, 0, &consumed) != VVA_OK || consumed != 0)
        return 0;
    return 1;
}

static int check_context_exact_truncation(void)
{
    /* One-symbol global table, one non-inherited context table, then 256
     * zero states. Both tables emit 0x2a without consuming any bits. */
    uint8_t encoded[2 + 2 + 32 + 3 + 2 + 512] = {2, 0, 1, 0x2a};
    memset(encoded + 4, 0xff, 32);
    encoded[4] &= (uint8_t)~1U;
    encoded[36] = 0;
    encoded[37] = 2;
    encoded[39] = 1;
    encoded[40] = 0x2a;

    for (size_t alignment = 0; alignment < 4; alignment++) {
        for (size_t length = 0; length <= sizeof(encoded); length++) {
            /* End the allocation at the supplied input end, except for
             * the zero-byte input's required non-NULL dummy address. */
            size_t storage_size = alignment + length;
            uint8_t *storage = malloc(storage_size ? storage_size : 1);
            if (!storage || !reset_allocator(0)) {
                free(storage);
                return 0;
            }
            uint8_t *source = storage + alignment;
            memcpy(source, encoded, length);
            uint8_t output[16];
            memset(output, 0xa5, sizeof(output));
            size_t consumed = SIZE_MAX;
            vva_error_t result = vva_decode_ctx(source, length, output,
                                               sizeof(output), 4, &consumed);
            free(storage);
            int complete = length == sizeof(encoded);
            if (result != (complete ? VVA_OK : VVA_ERR_CORRUPT) ||
                consumed != (complete ? sizeof(encoded) : SIZE_MAX) ||
                live_allocations != 0) {
                fprintf(stderr,
                        "FAIL: context prefix alignment=%zu bytes=%zu result=%d consumed=%zu live=%zu\n",
                        alignment, length, (int)result, consumed, live_allocations);
                return 0;
            }
            for (size_t i = 0; i < sizeof(output); i++) {
                if (output[i] != (complete && i < 4 ? 0x2a : 0xa5)) {
                    fprintf(stderr, "FAIL: context prefix changes unexpected output\n");
                    return 0;
                }
            }
        }
    }
    return 1;
}

static int check_context_roundtrip(void)
{
    uint8_t input[8192];
    uint8_t encoded[16384];
    uint8_t output[sizeof(input) + 1];
    size_t encoded_size = 0;
    size_t consumed = SIZE_MAX;
    for (size_t i = 0; i < sizeof(input); i++)
        input[i] = (uint8_t)((i / 31U + i / 7U) & 1U);

    if (!reset_allocator(0) ||
        vva_encode_ctx(input, sizeof(input), encoded, sizeof(encoded),
                       &encoded_size) != VVA_OK ||
        live_allocations != 0 || encoded_size >= sizeof(input)) {
        fprintf(stderr, "FAIL: context roundtrip fixture encoding\n");
        return 0;
    }
    memset(output, 0xa5, sizeof(output));
    if (!reset_allocator(0) ||
        vva_decode_ctx(encoded, encoded_size, output, sizeof(input),
                       sizeof(input), &consumed) != VVA_OK ||
        consumed > encoded_size || live_allocations != 0 ||
        memcmp(input, output, sizeof(input)) != 0 ||
        output[sizeof(input)] != 0xa5) {
        fprintf(stderr, "FAIL: context roundtrip decoding\n");
        return 0;
    }
    return 1;
}

static int check_single_stream_state_before_allocation(void)
{
    /* The sparse two-symbol table is valid; its initial state is missing,
     * truncated, exactly ANS_L, or the largest 16-bit value. */
    const uint8_t header[8] = {2, 2, 0, 1, 0, 1, 255, 15};
    const size_t sizes[] = {8, 9, 10, 10};
    for (size_t fixture = 0; fixture < sizeof(sizes) / sizeof(sizes[0]); fixture++) {
        size_t size = sizes[fixture];
        uint8_t *source = malloc(size);
        if (!source || !reset_allocator(0)) {
            free(source);
            return 0;
        }
        memcpy(source, header, sizeof(header));
        if (size > sizeof(header)) source[8] = fixture == 3 ? 255 : 0;
        if (size > sizeof(header) + 1) source[9] = fixture == 3 ? 255 : 16;
        uint8_t output[8];
        memset(output, 0xa5, sizeof(output));
        size_t consumed = SIZE_MAX;
        vva_error_t result = vva_decode(source, size, output, sizeof(output),
                                        sizeof(output), &consumed);
        free(source);
        if (result != VVA_ERR_CORRUPT || consumed != SIZE_MAX ||
            allocation_calls != 0 || live_allocations != 0) {
            fprintf(stderr,
                    "FAIL: single-stream state fixture=%zu result=%d consumed=%zu calls=%zu live=%zu\n",
                    fixture, (int)result, consumed, allocation_calls, live_allocations);
            return 0;
        }
        for (size_t i = 0; i < sizeof(output); i++)
            if (output[i] != 0xa5)
                return 0;
    }

    /* A single-symbol table has no initial state or bitstream on the wire. */
    const uint8_t single[] = {1, 0x2a};
    uint8_t output[8];
    memset(output, 0xa5, sizeof(output));
    size_t consumed = SIZE_MAX;
    if (!reset_allocator(0) ||
        vva_decode(single, sizeof(single), output, sizeof(output),
                   sizeof(output), &consumed) != VVA_OK ||
        consumed != sizeof(single) || allocation_calls != 0 || live_allocations != 0)
        return 0;
    for (size_t i = 0; i < sizeof(output); i++)
        if (output[i] != 0x2a)
            return 0;
    return 1;
}

static int check_reader_known_states(void)
{
    const uint8_t source[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xa6
    };
    /* Literal states keep this oracle independent of the bit-at-a-time
     * reference below. A zero-width read must not prefetch input; the
     * non-byte-aligned refill must leave the last byte for the tail. */
    const struct {
        int width;
        uint32_t value;
        uint64_t accumulator;
        int buffered;
        size_t position;
    } cases[] = {
        {0, 0, 0, 0, 0},
        {32, UINT32_C(0xffffffff), UINT64_C(0xffffffff), 32, 8},
        {27, UINT32_C(0x07ffffff), UINT64_C(0x1f), 5, 8},
        {32, UINT32_C(0xffffffff), UINT64_C(0x1fffffff), 29, 15},
        {32, UINT32_C(0xdfffffff), UINT64_C(0x14), 5, 16},
        {12, UINT32_C(0x14), 0, 0, 16},
        {32, 0, 0, 0, 16}
    };
    ans_br_t reader;
    ans_br_init(&reader, source, sizeof(source));
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint32_t value = ans_br_read(&reader, cases[i].width);
        if (value != cases[i].value || reader.a != cases[i].accumulator ||
            reader.n != cases[i].buffered || reader.p != cases[i].position ||
            reader.s != source || reader.l != sizeof(source)) {
            fprintf(stderr,
                    "FAIL: ANS reader known-state step=%zu width=%d n=%d p=%zu\n",
                    i, cases[i].width, reader.n, reader.p);
            return 0;
        }
    }
    return 1;
}

static int check_reader_zero_extension(void)
{
    uint8_t storage[20];
    for (size_t i = 0; i < sizeof(storage); i++)
        storage[i] = (uint8_t)(i * 37U + 11U);

    for (size_t alignment = 0; alignment < 4; alignment++) {
        for (size_t length = 0; length <= 16; length++) {
            /* Cover the helper's full 0..32-bit contract, including widths
             * wider than literal states (12) and sequence offsets (23).
             * The final mode mixes widths across refill boundaries. */
            for (int mode = 0; mode <= 33; mode++) {
                ans_br_t reader = {UINT64_MAX, 64, NULL, SIZE_MAX, SIZE_MAX};
                const uint8_t *source = storage + alignment;
                size_t bit = 0;
                ans_br_init(&reader, source, length);
                if (reader.a != 0 || reader.n != 0 || reader.p != 0 ||
                    reader.s != source || reader.l != length) {
                    fprintf(stderr, "FAIL: reader initialization retains stale state\n");
                    return 0;
                }
                for (size_t read = 0; read < 160; read++) {
                    int width = mode < 33 ? mode :
                        (int)((read * 7 + length * 3 + alignment) % 33);
                    uint32_t expected = 0;
                    for (int i = 0; i < width; i++, bit++) {
                        if (bit < length * 8)
                            expected |= (uint32_t)((source[bit / 8] >>
                                         (bit % 8)) & 1U) << i;
                    }
                    uint32_t actual = ans_br_read(&reader, width);
                    if (actual != expected || reader.n < 0 || reader.n > 64 ||
                        reader.p > length) {
                        fprintf(stderr,
                                "FAIL: reader alignment=%zu length=%zu width=%d read=%zu n=%d\n",
                                alignment, length, width, read, reader.n);
                        return 0;
                    }
                }
            }
        }
    }
    return 1;
}

static int check_reader_fill_states(void)
{
    const size_t prefixes[] = {0, 1, 7};
    const uint64_t accumulators[] = {
        0, 1, UINT64_MAX, UINT64_C(0x8000000000000000),
        UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x5555555555555555)
    };
    size_t checked = 0;

    for (size_t alignment = 0; alignment < 4; alignment++) {
        for (size_t prefix = 0; prefix < sizeof(prefixes) / sizeof(prefixes[0]); prefix++) {
            for (size_t remaining = 0; remaining <= 16; remaining++) {
                size_t length = prefixes[prefix] + remaining;
                size_t allocation = alignment + length;
                /* A nonempty span ends exactly at the allocation boundary.
                 * malloc(0) is avoided; exhausted NULL sources are tested
                 * separately below. */
                if (!allocation)
                    allocation = 1;
                uint8_t *storage = malloc(allocation);
                if (!storage) {
                    fprintf(stderr, "FAIL: reader fill test allocation\n");
                    return 0;
                }
                uint8_t original[26];
                for (size_t i = 0; i < allocation; i++)
                    storage[i] = (uint8_t)(i * 37U + 11U);
                memcpy(original, storage, allocation);
                const uint8_t *source = storage + alignment;

                for (int count = 0; count <= 64; count++) {
                    for (size_t a = 0; a < sizeof(accumulators) / sizeof(accumulators[0]); a++) {
                        /* Include synthetic accumulator bits above count:
                         * refill is an OR, not a replacement of those bits. */
                        uint64_t expected_a = accumulators[a];
                        int expected_n = count;
                        size_t expected_p = prefixes[prefix];
                        while (expected_n <= 56 && expected_p < length) {
                            expected_a |= (uint64_t)source[expected_p++] << expected_n;
                            expected_n += 8;
                        }
                        ans_br_t reader = {accumulators[a], count, source,
                                           prefixes[prefix], length};
                        /* A second fill must be a no-op: the first either
                         * exhausts the source or leaves more than 56 bits. */
                        for (int repeat = 0; repeat < 2; repeat++) {
                            ans_br_fill(&reader);
                            if (reader.a != expected_a || reader.n != expected_n ||
                                reader.s != source || reader.p != expected_p ||
                                reader.l != length || memcmp(storage, original, allocation)) {
                                fprintf(stderr,
                                        "FAIL: reader fill alignment=%zu prefix=%zu remaining=%zu count=%d accumulator=%zu repeat=%d\n",
                                        alignment, prefixes[prefix], remaining, count, a, repeat);
                                free(storage);
                                return 0;
                            }
                        }
                        checked++;
                    }
                }
                free(storage);
            }
        }
    }
    if (checked != 79560) {
        fprintf(stderr, "FAIL: reader fill state count=%zu\n", checked);
        return 0;
    }
    return 1;
}

static int check_reader_exhausted_positions(void)
{
    const size_t positions[] = {0, 1, 7, 8, 9, SIZE_MAX - 8,
                                SIZE_MAX - 7, SIZE_MAX};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); i++) {
        for (int count = 0; count <= 64; count++) {
            /* These are synthetic counters, not purported giant buffers.
             * With p == l no source bytes remain, so refill must not form
             * a source pointer or read from the deliberately NULL source. */
            ans_br_t reader = {0, count, NULL, positions[i], positions[i]};
            ans_br_fill(&reader);
            if (reader.a != 0 || reader.n != count || reader.s != NULL ||
                reader.p != positions[i] || reader.l != positions[i]) {
                fprintf(stderr, "FAIL: exhausted refill changes reader state\n");
                return 0;
            }
            int buffered = count;
            for (int width = 0; width <= 32; width++) {
                buffered = buffered >= width ? buffered - width : 0;
                if (ans_br_read(&reader, width) != 0 || reader.a != 0 ||
                    reader.n != buffered || reader.s != NULL ||
                    reader.p != positions[i] || reader.l != positions[i]) {
                    fprintf(stderr,
                            "FAIL: exhausted read position=%zu count=%d width=%d\n",
                            positions[i], count, width);
                    return 0;
                }
            }
        }
    }
    return 1;
}

static int check_reader_exhausted_preservation(void)
{
    const size_t positions[] = {0, 1, 7, 8, 9, SIZE_MAX - 8,
                                SIZE_MAX - 7, SIZE_MAX};
    const uint64_t accumulators[] = {
        0, 1, UINT64_MAX, UINT64_C(0x8000000000000000),
        UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x5555555555555555)
    };
    const uint8_t byte = 0xa5;

    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); i++) {
        for (int count = 0; count <= 64; count++) {
            for (size_t a = 0; a < sizeof(accumulators) / sizeof(accumulators[0]); a++) {
                for (int source_kind = 0; source_kind < 3; source_kind++) {
                    ans_br_t reader = {accumulators[a], count, NULL,
                                       positions[i], positions[i]};
                    /* No source byte exists at p == l. Even a pointer into
                     * the reader itself must be left alone, not prefetched. */
                    const uint8_t *source = source_kind == 0 ? NULL :
                        source_kind == 1 ? &byte : (const uint8_t *)&reader;
                    reader.s = source;
                    ans_br_fill(&reader);
                    if (reader.a != accumulators[a] || reader.n != count ||
                        reader.s != source || reader.p != positions[i] ||
                        reader.l != positions[i]) {
                        fprintf(stderr,
                                "FAIL: exhausted preservation position=%zu count=%d accumulator=%zu source=%d\n",
                                positions[i], count, a, source_kind);
                        return 0;
                    }
                }
            }
        }
    }
    return 1;
}

static int check_exhausted_literal_streams(void)
{
    /* Symbol 0 has frequency 1 and state 0 consumes 12 implicit zero bits.
     * Symbol 1 supplies the remaining 4095 entries. */
    uint8_t single[18] = {2, 2, 0, 1, 0, 1, 255, 15};
    uint8_t parallel[32] = {2, 2, 0, 1, 0, 1, 255, 15};
    uint8_t output[4096];
    const size_t lengths[2] = {10, sizeof(single)};
    const size_t consumed_lengths[2] = {10, 12};

    for (size_t i = 0; i < 2; i++) {
        size_t consumed = 0;
        memset(output, 0xa5, sizeof(output));
        if (!reset_allocator(0) ||
            vva_decode(single, lengths[i], output, sizeof(output), 1,
                       &consumed) != VVA_OK || output[0] != 0 ||
            output[1] != 0xa5 || consumed != consumed_lengths[i] ||
            live_allocations != 0) {
            fprintf(stderr, "FAIL: single-stream zero extension or consumption\n");
            return 0;
        }
    }

    for (size_t size = 1; size <= sizeof(output); size++) {
        size_t consumed = 0;
        memset(output, 0xa5, sizeof(output));
        if (!reset_allocator(0) ||
            vva_decode4(parallel, sizeof(parallel), output, sizeof(output),
                        size, &consumed) != VVA_OK ||
            consumed != sizeof(parallel) || live_allocations != 0)
            return 0;
        for (size_t i = 0; i < sizeof(output); i++) {
            if (output[i] != (i < size ? 0 : 0xa5)) {
                fprintf(stderr, "FAIL: ANS4 zero extension or tail size=%zu\n", size);
                return 0;
            }
        }
    }
    return 1;
}

static int check_mixed_literal_lanes(void)
{
    /* Synthetic accepted input, not encoder output. State 0 emits symbol 0
     * and consumes 12 bits. Lane 1's ff then reaches state 255, which emits
     * symbol 1 without consuming bits; the other lanes stay at state 0. */
    const uint8_t fixture[50] = {
        2, 2, 0, 1, 0, 1, 255, 15,
        [20] = 1, [24] = 8, [28] = 9, [32] = 0xff
    };
    const uint8_t expected[36] = {
        0, 0, 0, 0,
        0, 1, 0, 0, 0, 1, 0, 0,
        0, 1, 0, 0, 0, 1, 0, 0,
        0, 1, 0, 0, 0, 1, 0, 0,
        0, 1, 0, 0, 0, 1, 0, 0
    };
    size_t workspace_size = vva_decode_workspace_size();
    void *workspace = malloc(workspace_size);
    uint8_t *source_storage = NULL, *output_storage = NULL;
    int ok = 0;
    if (!workspace)
        goto cleanup;
    memset(workspace, 0x5a, workspace_size);

    for (size_t alignment = 0; alignment < 4; alignment++) {
        /* Both exposed spans end at their allocation boundary. Sanitizers
         * must see an overread/overwrite, not undocumented spare padding. */
        source_storage = malloc(sizeof(fixture) + alignment);
        if (!source_storage)
            goto cleanup;
        uint8_t *source = source_storage + alignment;
        memcpy(source, fixture, sizeof(fixture));
        for (size_t size = 1; size <= sizeof(expected); size++) {
            output_storage = malloc(size + alignment);
            if (!output_storage)
                goto cleanup;
            uint8_t *output = output_storage + alignment;
            for (int mode = 0; mode < 2; mode++) {
                memset(output_storage, 0xa5, size + alignment);
                size_t consumed = SIZE_MAX;
                if (!reset_allocator(0))
                    goto cleanup;
                vva_error_t result = mode == 0 ?
                    vva_decode4(source, sizeof(fixture), output, size,
                                size, &consumed) :
                    vva_decode4_with_workspace(source, sizeof(fixture), output,
                                              size, size, &consumed, workspace,
                                              workspace_size);
                if (result != VVA_OK || consumed != sizeof(fixture) ||
                    allocation_calls != (mode == 0 ? 1U : 0U) ||
                    live_allocations != 0) {
                    fprintf(stderr,
                            "FAIL: ANS4 mixed lanes alignment=%zu size=%zu mode=%d result=%d consumed=%zu calls=%zu live=%zu\n",
                            alignment, size, mode, (int)result, consumed,
                            allocation_calls, live_allocations);
                    goto cleanup;
                }
                for (size_t i = 0; i < size + alignment; i++) {
                    uint8_t want = i < alignment ? 0xa5 : expected[i - alignment];
                    if (output_storage[i] != want) {
                        fprintf(stderr,
                                "FAIL: ANS4 mixed lanes alignment=%zu size=%zu mode=%d byte=%zu got=%u want=%u\n",
                                alignment, size, mode, i,
                                (unsigned int)output_storage[i], (unsigned int)want);
                        goto cleanup;
                    }
                }
            }
            free(output_storage);
            output_storage = NULL;
        }
        free(source_storage);
        source_storage = NULL;
    }
    ok = 1;
cleanup:
    free(output_storage);
    free(source_storage);
    free(workspace);
    return ok;
}

static int check_sequence_literal_section_rejected_before_allocation(void)
{
    /* A SEQ/T payload declares one literal but supplies no literal section.
     * No valid literal encoding can produce that byte, so rejection must
     * happen before the decoder reserves its 48-KiB table workspace. */
    const uint8_t malformed[9] = {1, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t truncated[25] = {0};
    const size_t truncated_lengths[] = {9, 13, 15, 17, 19, 25};
    uint8_t output[1] = {0xa5};
    size_t output_size = SIZE_MAX;
    vva_error_t result;

    if (!reset_allocator(0))
        return 0;
    result = vva_decode_sequences(malformed, sizeof(malformed), output,
                                  sizeof(output), &output_size, output);
    if (result != VVA_ERR_CORRUPT ||
        allocation_calls != 0 || live_allocations != 0 ||
        output[0] != 0xa5 || output_size != SIZE_MAX) {
        fprintf(stderr,
                "FAIL: SEQ literal section result=%d calls=%zu live=%zu output=%u size=%zu\n",
                (int)result,
                allocation_calls, live_allocations, (unsigned int)output[0], output_size);
        return 0;
    }

    /* A zero-literal header still needs the match count and table headers.
     * Reject this truncated prefix before reserving the same table workspace. */
    for (size_t i = 0; i < sizeof(truncated_lengths) / sizeof(truncated_lengths[0]); i++) {
        memset(output, 0xa5, sizeof(output));
        output_size = SIZE_MAX;
        if (!reset_allocator(0))
            return 0;
        result = vva_decode_sequences(truncated, truncated_lengths[i], output,
                                      sizeof(output), &output_size, output);
        if (result != VVA_ERR_CORRUPT ||
            allocation_calls != 0 || live_allocations != 0 ||
            output[0] != 0xa5 || output_size != SIZE_MAX) {
            fprintf(stderr,
                    "FAIL: truncated SEQ prefix bytes=%zu result=%d calls=%zu live=%zu output=%u size=%zu\n",
                    truncated_lengths[i], (int)result,
                    allocation_calls, live_allocations,
                    (unsigned int)output[0], output_size);
            return 0;
        }
    }
    return 1;
}

static int check_sequence_window_before_allocation(void)
{
    /* Empty, complete sequence envelope: no tables or bitstream are used. */
    const uint8_t encoded[29] = {0};
    const uint32_t windows[] = {0, (UINT32_C(1) << 24) + 1, UINT32_MAX};
    for (size_t i = 0; i < sizeof(windows) / sizeof(windows[0]); i++) {
        for (int version = 0; version < 2; version++) {
            uint8_t output = 0xa5;
            size_t output_size = SIZE_MAX;
            if (!reset_allocator(0))
                return 0;
            vva_error_t result = version
                ? vva_decode_sequences_v2_limited(encoded, sizeof(encoded),
                    &output, sizeof(output), &output_size, &output, windows[i])
                : vva_decode_sequences_limited(encoded, sizeof(encoded),
                    &output, sizeof(output), &output_size, &output, windows[i]);
            if (result != VVA_ERR_CORRUPT || allocation_calls != 0 ||
                live_allocations != 0 || output != 0xa5 || output_size != SIZE_MAX) {
                fprintf(stderr, "FAIL: sequence window=%u version=%d calls=%zu live=%zu result=%d\n",
                        windows[i], version, allocation_calls, live_allocations, (int)result);
                return 0;
            }
        }
    }
    return 1;
}

static int check_sequence_tables_before_allocation(void)
{
    const uint8_t empty[29] = {0};
    uint8_t literal_without_table[30] = {1};
    uint8_t match_without_tables[29] = {0};
    uint8_t invalid_symbol[31] = {0};
    uint8_t empty_with_unused_data[34] = {0};
    literal_without_table[5] = 1;
    literal_without_table[9] = 0x2a;
    match_without_tables[9] = 1;
    invalid_symbol[13] = 2;
    invalid_symbol[15] = 1;
    invalid_symbol[16] = 255;
    /* Preserve legacy tolerance of unused literal bytes, tables, states
     * and bitstream bytes when the sequence produces no output. */
    empty_with_unused_data[4] = 255;
    empty_with_unused_data[5] = 1;
    empty_with_unused_data[9] = 0x2a;
    empty_with_unused_data[14] = 2;
    empty_with_unused_data[16] = 1;
    memset(empty_with_unused_data + 22, 255, 6);
    empty_with_unused_data[28] = 2;
    empty_with_unused_data[32] = 0xaa;
    empty_with_unused_data[33] = 0xbb;
    const uint8_t *inputs[] = {literal_without_table, match_without_tables,
                               invalid_symbol, empty, empty_with_unused_data};
    const size_t lengths[] = {sizeof(literal_without_table),
                               sizeof(match_without_tables),
                               sizeof(invalid_symbol), sizeof(empty),
                               sizeof(empty_with_unused_data)};
    for (size_t fixture = 0; fixture < sizeof(lengths) / sizeof(lengths[0]); fixture++) {
        for (int version = 0; version < 2; version++) {
            uint8_t output = 0xa5;
            size_t output_size = SIZE_MAX;
            if (!reset_allocator(0))
                return 0;
            vva_error_t result = version
                ? vva_decode_sequences_v2(inputs[fixture], lengths[fixture],
                    &output, sizeof(output), &output_size, &output)
                : vva_decode_sequences(inputs[fixture], lengths[fixture],
                    &output, sizeof(output), &output_size, &output);
            int valid_empty = fixture >= 3;
            if (result != (valid_empty ? VVA_OK : VVA_ERR_CORRUPT) ||
                output_size != (valid_empty ? 0 : SIZE_MAX) || output != 0xa5 ||
                allocation_calls != 0 || live_allocations != 0) {
                fprintf(stderr, "FAIL: sequence table fixture=%zu version=%d calls=%zu live=%zu result=%d\n",
                        fixture, version, allocation_calls, live_allocations, (int)result);
                return 0;
            }
        }
    }
    return 1;
}

static int check_logarithm_boundaries(void)
{
    if (ilog2(0) != 0 || ilog2(UINT32_MAX) != 31)
        return 0;
    for (unsigned int exponent = 0; exponent < 32; exponent++) {
        uint32_t power = UINT32_C(1) << exponent;
        if (ilog2(power) != (int)exponent ||
            ilog2(power - 1) != (exponent == 0 ? 0 : (int)exponent - 1) ||
            ilog2(power + 1) != (exponent == 0 ? 1 : (int)exponent))
            return 0;
    }
    int expected = 0;
    uint32_t next_power = 2;
    for (uint32_t value = 0; value <= ANS_L; value++) {
        if (value == next_power) {
            expected++;
            next_power *= 2;
        }
        if (ilog2(value) != expected)
            return 0;
    }
    return 1;
}

static int check_frequency_result(const uint16_t norm[NSYM], int expected,
                                  int expected_single)
{
    int single = -1;
    int result = validated_symbol_count(norm, &single);
    if (result != expected || single != expected_single) {
        fprintf(stderr, "FAIL: ANS frequency validation result=%d/%d single=%d/%d\n",
                result, expected, single, expected_single);
        return 0;
    }
    return 1;
}

static int check_frequency_validation(void)
{
    uint16_t norm[NSYM] = {0};
    if (!check_frequency_result(norm, 0, -1))
        return 0;
    norm[NSYM - 1] = ANS_L;
    if (!check_frequency_result(norm, 1, NSYM - 1))
        return 0;
    norm[0] = 1;
    norm[NSYM - 1] = ANS_L - 1;
    if (!check_frequency_result(norm, 2, NSYM - 1))
        return 0;
    norm[NSYM - 1]--;
    if (!check_frequency_result(norm, 0, NSYM - 1))
        return 0;
    norm[NSYM - 1] += 2;
    if (!check_frequency_result(norm, 0, NSYM - 1))
        return 0;
    for (int i = 0; i < NSYM; i++)
        norm[i] = ANS_L / NSYM;
    if (!check_frequency_result(norm, NSYM, NSYM - 1))
        return 0;
    for (int i = 0; i < NSYM; i++)
        norm[i] = UINT16_MAX;
    if (!check_frequency_result(norm, 0, NSYM - 1))
        return 0;
    memset(norm, 0, sizeof(norm));
    /* This invalid sum is 4096 modulo 65536: a 16-bit total would accept it. */
    norm[0] = UINT16_MAX;
    norm[1] = ANS_L + 1;
    return check_frequency_result(norm, 0, 1);
}

static int check_table_bounds(const uint16_t norm[NSYM], unsigned int split)
{
    vva_dec_entry_t table[ANS_L];
    uint32_t occurrences[NSYM] = {0};
    memset(table, 0xa5, sizeof(table));
    if (!build_dec_direct(norm, table)) {
        fprintf(stderr, "FAIL: ANS normalized table rejected split=%u\n", split);
        return 0;
    }
    for (size_t i = 0; i < ANS_L; i++) {
        vva_dec_entry_t entry = table[i];
        if (entry.nbits > ANS_LOG) {
            fprintf(stderr, "FAIL: ANS table width split=%u slot=%zu bits=%u\n",
                    split, i, (unsigned int)entry.nbits);
            return 0;
        }
        uint32_t extra = (UINT32_C(1) << entry.nbits) - 1;
        if (entry.baseline >= ANS_L || extra > ANS_L - 1U - entry.baseline ||
            norm[entry.symbol] == 0) {
            fprintf(stderr, "FAIL: ANS table state range split=%u slot=%zu\n", split, i);
            return 0;
        }
        occurrences[entry.symbol]++;
    }
    for (int symbol = 0; symbol < NSYM; symbol++) {
        if (occurrences[symbol] != norm[symbol]) {
            fprintf(stderr, "FAIL: ANS table multiplicity split=%u symbol=%d\n", split, symbol);
            return 0;
        }
    }
    return 1;
}

static int check_table_frequency_splits(void)
{
    uint16_t norm[NSYM] = {0};
    for (unsigned int split = 0; split <= ANS_L; split++) {
        norm[0] = (uint16_t)split;
        norm[NSYM - 1] = (uint16_t)(ANS_L - split);
        if (!check_table_bounds(norm, split))
            return 0;
    }
    for (int symbol = 0; symbol < NSYM; symbol++)
        norm[symbol] = ANS_L / NSYM;
    return check_table_bounds(norm, ANS_L + 1U);
}

int main(void)
{
    if (!check_table_frequency_splits())
        return 1;
    if (!check_frequency_validation())
        return 1;
    if (!check_logarithm_boundaries()) {
        fprintf(stderr, "FAIL: ANS logarithm powers, neighbors and table frequencies\n");
        return 1;
    }
    if (!check_reader_known_states())
        return 1;
    if (!check_reader_zero_extension())
        return 1;
    if (!check_reader_fill_states())
        return 1;
    if (!check_reader_exhausted_positions())
        return 1;
    if (!check_reader_exhausted_preservation())
        return 1;
    if (!check_exhausted_literal_streams())
        return 1;
    if (!check_mixed_literal_lanes())
        return 1;
    if (!check_sequence_literal_section_rejected_before_allocation())
        return 1;
    if (!check_context_exact_truncation() || !check_context_roundtrip())
        return 1;
    if (!check_single_stream_state_before_allocation())
        return 1;
    if (!check_sequence_window_before_allocation())
        return 1;
    if (!check_sequence_tables_before_allocation())
        return 1;
    uint8_t input[4096];
    for (size_t i = 0; i < sizeof(input); i++)
        input[i] = (uint8_t)((i * 37U + i / 7U) & 15U);

    for (size_t ordinal = 1; ordinal <= 5; ordinal++) {
        if (!check_failure(ordinal, input, sizeof(input)))
            return 1;
    }
    if (!check_invalid_decode_arguments()) {
        fprintf(stderr, "FAIL: decoder argument validation\n");
        return 1;
    }
    if (!check_success(input, sizeof(input)))
        return 1;

    puts("PASS: ANS4 allocation failures release all owned storage (5 cases)");
    puts("PASS: invalid sequence windows are rejected before allocation (6 cases)");
    puts("PASS: invalid sequence tables and valid empty sequences need no allocation (10 cases)");
    puts("PASS: ANS, ANS4 and context decoders reject NULL and undersized arguments");
    puts("PASS: ANS4 successful encode/decode releases all owned storage");
    puts("PASS: ANS reader known states preserve zero-width, masked refill and EOF behavior (7 steps)");
    puts("PASS: ANS reader reset and zero extension keep bit counts bounded (2312 cases)");
    puts("PASS: ANS refill matches the byte oracle and is idempotent (79560 initial states, two fills each)");
    puts("PASS: exhausted ANS reader does not access its source (520 synthetic counter cases)");
    puts("PASS: exhausted ANS refill preserves accumulator and source aliases (9360 synthetic states)");
    puts("PASS: single-stream consumption and ANS4 lengths 1..4096 preserve zero extension");
    puts("PASS: ANS4 mixed lane EOF preserves bytes, bounds, consumption and workspace reuse (288 cases)");
    puts("PASS: SEQ rejects missing literal data and a truncated prefix before scratch allocation");
    puts("PASS: context ANS exact-size prefixes and zero extension (2216 cases)");
    puts("PASS: context ANS encoder/decoder roundtrip releases all owned storage");
    puts("PASS: single-stream ANS rejects malformed states before allocation; single-symbol headers need no state");
    puts("PASS: ANS logarithm boundaries and table frequencies (4195 checks)");
    puts("PASS: ANS frequency validation covers empty, 1/2/256 symbols, invalid totals and 16-bit wrap (8 cases)");
    puts("PASS: ANS table bounds and multiplicities (4097 frequency splits plus uniform 256-symbol table, 16785408 entries)");
    return 0;
}
