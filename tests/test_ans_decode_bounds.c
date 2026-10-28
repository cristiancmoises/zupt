/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Exact-sized ANS4 metadata and sequence fixtures for native and Frama-C checks.
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "vv_ans.h"

#ifdef __FRAMAC__
/* Eva witnesses keep successful paths visible without dumping entire tables. */
extern void Frama_C_show_each_metadata(vva_error_t result, size_t consumed);
extern void Frama_C_show_each_literal_tail(size_t written, uint8_t last);
extern void Frama_C_show_each_match_tail(int version2, size_t literals,
                                        size_t written, uint8_t last);
#endif

static void check_match_tail(const uint8_t *source, size_t source_size,
                             uint8_t *output, size_t output_size,
                             size_t literals, int version2)
{
    size_t written = SIZE_MAX;
    vva_error_t result;
    if (version2)
        result = vva_decode_sequences_v2(source, source_size, output,
                                         output_size, &written, output);
    else
        result = vva_decode_sequences(source, source_size, output,
                                      output_size, &written, output);
#ifdef __FRAMAC__
    if (result == VVA_ERR_NOMEM)
        return;
#endif
    assert(result == VVA_OK);
    assert(written == output_size);
    for (size_t i = 0; i < literals; i++)
        assert(output[i] == 'A' + i);
    for (size_t i = literals; i < output_size; i++)
        assert(output[i] == 'A' + i - literals);
#ifdef __FRAMAC__
    Frama_C_show_each_match_tail(version2, literals, written,
                                 output[output_size - 1]);
#endif
}

int main(void)
{
    /* Two equally frequent symbols force the multi-symbol decode path. */
    uint8_t short_metadata[8] = {2, 2, 0, 0, 8, 1, 0, 8};
    uint8_t oversized_lane[32] = {2, 2, 0, 0, 8, 1, 0, 8};
    uint8_t output[4] = {0};
    size_t consumed = 0;
    vva_error_t result;

    result = vva_decode4(short_metadata, sizeof(short_metadata), output,
                         sizeof(output), sizeof(output), &consumed);
    assert(result == VVA_ERR_CORRUPT);
    assert(consumed == 0);

    /* States occupy bytes 8..15; the first lane length starts at byte 16. */
    oversized_lane[16] = 255;
    oversized_lane[17] = 255;
    oversized_lane[18] = 255;
    oversized_lane[19] = 255;
    result = vva_decode4(oversized_lane, sizeof(oversized_lane), output,
                         sizeof(output), sizeof(output), &consumed);
    assert(result == VVA_ERR_CORRUPT);
    assert(consumed == 0);
    for (size_t i = 0; i < sizeof(output); i++)
        assert(output[i] == 0);

    /* Each nonempty lane fits alone, but lane 0 consumes the only payload
     * byte before lane 3 is checked. No output or consumption is committed. */
    uint8_t cumulative_lanes[33] = {2, 2, 0, 0, 8, 1, 0, 8};
    uint8_t cumulative_output[4] = {0xa5, 0xa5, 0xa5, 0xa5};
    cumulative_lanes[16] = 1;
    cumulative_lanes[28] = 1;
    consumed = SIZE_MAX;
    result = vva_decode4(cumulative_lanes, sizeof(cumulative_lanes),
                         cumulative_output, sizeof(cumulative_output),
                         sizeof(cumulative_output), &consumed);
    assert(result == VVA_ERR_CORRUPT);
    assert(consumed == SIZE_MAX);
    for (size_t i = 0; i < sizeof(cumulative_output); i++)
        assert(cumulative_output[i] == 0xa5);
#ifdef __FRAMAC__
    Frama_C_show_each_metadata(result, consumed);
#endif

    /* One literal-only sequence, with no destination padding. The short
     * tail must not form a pointer beyond the output object just to decide
     * whether the wider copy fits. */
    const uint8_t literal_tail[] = {
        4, 0, 0, 0, 0, 4, 0, 0, 0, 'A', 'B', 'C', 'D',
        0, 0, 0, 0, 0, 0, 0, 0, 2, 0, VVA_HDR_SINGLE, 4,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    uint8_t exact_output[4] = {0};
    size_t written = SIZE_MAX;
    result = vva_decode_sequences(literal_tail, sizeof(literal_tail),
                                  exact_output, sizeof(exact_output),
                                  &written, exact_output);
#ifdef __FRAMAC__
    /* Eva also explores allocation failure. Native runs require success. */
    if (result == VVA_ERR_NOMEM)
        return 0;
#endif
    assert(result == VVA_OK);
    assert(written == sizeof(exact_output));
    assert(exact_output[0] == 'A' && exact_output[1] == 'B' &&
           exact_output[2] == 'C' && exact_output[3] == 'D');
#ifdef __FRAMAC__
    Frama_C_show_each_literal_tail(written, exact_output[3]);
#endif

    /* Single-symbol ML/OF/LL tables describe one match at distance 16 or
     * 8. Zero extra bits select the smallest length: four bytes in v1,
     * three in v2. Each destination ends exactly at that match's tail. */
    const uint8_t match16[] = {
        16, 0, 0, 0, 0, 16, 0, 0, 0,
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        1, 0, 0, 0,
        2, 0, VVA_HDR_SINGLE, 0,
        2, 0, VVA_HDR_SINGLE, 7,
        2, 0, VVA_HDR_SINGLE, 16,
        0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0
    };
    const uint8_t match8[] = {
        8, 0, 0, 0, 0, 8, 0, 0, 0,
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        1, 0, 0, 0,
        2, 0, VVA_HDR_SINGLE, 0,
        2, 0, VVA_HDR_SINGLE, 6,
        2, 0, VVA_HDR_SINGLE, 8,
        0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0
    };
    uint8_t output16_v1[20] = {0};
    uint8_t output16_v2[19] = {0};
    uint8_t output8_v1[12] = {0};
    uint8_t output8_v2[11] = {0};
    check_match_tail(match16, sizeof(match16), output16_v1,
                     sizeof(output16_v1), 16, 0);
    check_match_tail(match16, sizeof(match16), output16_v2,
                     sizeof(output16_v2), 16, 1);
    check_match_tail(match8, sizeof(match8), output8_v1,
                     sizeof(output8_v1), 8, 0);
    check_match_tail(match8, sizeof(match8), output8_v2,
                     sizeof(output8_v2), 8, 1);
    return 0;
}
