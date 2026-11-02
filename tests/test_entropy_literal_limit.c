/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Entropy literal counts cannot exceed the block output size.  Reject that
 * malformed envelope before allocating a literal buffer or entropy table.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/vaptvupt.h"

static size_t allocation_calls;

void *observed_malloc(size_t size);

void *observed_malloc(size_t size)
{
    allocation_calls++;
    return malloc(size);
}

static int check_tag(uint8_t tag, const char *name, unsigned output_size,
                     size_t expected_allocations)
{
    /* A two-literal envelope with no entropy bytes. A one-byte block must
     * reject it before allocation; a two-byte block reaches allocation and
     * then rejects the empty entropy stream, checking the observer itself. */
    uint8_t frame[] = {
        0x00, 0x01, 0x56, 0x56, 0x01, 0x00, 0x00, 0x10,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00,
        0x00,
        0x02, 0x00, 0x00, 0x00
    };
    uint8_t output[2] = {0xa5, 0xa5};

    frame[8] = (uint8_t)output_size;
    frame[16] = (uint8_t)((output_size << 3) | 7u);
    frame[23] = tag;
    allocation_calls = 0;
    int64_t result = vv_decompress(frame, sizeof(frame), output, output_size);
    if (result != VV_ERR_CORRUPT || allocation_calls != expected_allocations ||
        output[0] != 0xa5 || output[1] != 0xa5) {
        fprintf(stderr, "FAIL: %s size=%u result=%lld allocations=%zu/%zu output=%u,%u\n",
                name, output_size, (long long)result, allocation_calls,
                expected_allocations, (unsigned)output[0], (unsigned)output[1]);
        return 0;
    }
    return 1;
}

int main(void)
{
    static const struct {
        uint8_t tag;
        const char *name;
    } cases[] = {
        {VV_ENTROPY_HUFFMAN, "Huffman"},
        {VV_ENTROPY_ANS, "ANS"},
        {VV_ENTROPY_ANS4, "ANS4"},
        {VV_ENTROPY_CTX, "context ANS"}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (!check_tag(cases[i].tag, cases[i].name, 1, 0) ||
            !check_tag(cases[i].tag, cases[i].name, 2, 1))
            return 1;
    }

    puts("PASS: entropy literal counts above block output are rejected before allocation");
    return 0;
}
