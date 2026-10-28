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

void *__real_malloc(size_t size);
void __real_free(void *pointer);
void *__wrap_malloc(size_t size);
void __wrap_free(void *pointer);

static size_t allocation_calls;

void *__wrap_malloc(size_t size)
{
    allocation_calls++;
    return __real_malloc(size);
}

void __wrap_free(void *pointer)
{
    __real_free(pointer);
}

static int check_tag(uint8_t tag, const char *name)
{
    /* Frame header, last entropy block (one output byte), a five-byte
     * entropy section, then [lit_count=2, encoded_section_size=0]. */
    uint8_t frame[] = {
        0x00, 0x01, 0x56, 0x56, 0x01, 0x00, 0x00, 0x10,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00,
        0x00,
        0x02, 0x00, 0x00, 0x00
    };
    uint8_t output = 0xa5;

    frame[23] = tag;
    allocation_calls = 0;
    int64_t result = vv_decompress(frame, sizeof(frame), &output, sizeof(output));
    if (result != VV_ERR_CORRUPT || allocation_calls != 0 || output != 0xa5) {
        fprintf(stderr, "FAIL: %s result=%lld allocations=%zu output=%u\n",
                name, (long long)result, allocation_calls, (unsigned)output);
        return 0;
    }
    return 1;
}

int main(void)
{
    if (!check_tag(VV_ENTROPY_HUFFMAN, "Huffman") ||
        !check_tag(VV_ENTROPY_ANS, "ANS") ||
        !check_tag(VV_ENTROPY_ANS4, "ANS4") ||
        !check_tag(VV_ENTROPY_CTX, "context ANS"))
        return 1;

    puts("PASS: entropy literal counts above block output are rejected before allocation");
    return 0;
}
