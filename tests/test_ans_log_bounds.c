/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (c) 2026 Cristian Cezar Moisés */
#include "__fc_builtin.h"
#include "../src/vv_ans.c"
#include <limits.h>

#if UINT_MAX != UINT32_MAX
#error unsigned_int_must_match_uint32
#endif

/* Analyze the real helper over every admitted value, not sampled fixtures.
 * The two calls keep the table-input range distinct from the full range. */
int main(void)
{
    uint32_t input = Frama_C_unsigned_int_interval(0, UINT32_MAX);
    int bits = ilog2(input);
    /*@ assert uint32_width: 0 <= bits <= 31; */
    uint32_t frequency = Frama_C_unsigned_int_interval(0, ANS_L);
    int frequency_bits = ilog2(frequency);
    /*@ assert table_width: 0 <= frequency_bits <= ANS_LOG; */
    return 0;
}
