/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 *
 * Exercise the actual private estimator without exporting a library symbol.
 * The binary transcript is compared with pre-fix output by the shell test.
 */
#include "../src/vv_ans.c"
#include <math.h>
#include <stdio.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static unsigned histograms, streams, formats[5];

static void fail(const char *what, unsigned id) {
    fprintf(stderr, "FAIL: %s (case %u)\n", what, id);
    exit(1);
}

static void write_bytes(const void *data, size_t size) {
    if (fwrite(data, 1, size, stdout) != size) fail("transcript write", 0);
}

static void write_u32(uint32_t value) {
    uint8_t bytes[4] = {(uint8_t)value, (uint8_t)(value >> 8),
                        (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    write_bytes(bytes, sizeof(bytes));
}

static void check_histogram(const uint32_t freq[NSYM], int require_deep) {
    uint8_t lengths[NSYM];
    memset(lengths, 0xa5, sizeof(lengths));
    est_huff_lengths(freq, lengths);
    unsigned active = 0, deepest = 0;
    long double kraft = 0;
    for (int symbol = 0; symbol < NSYM; symbol++) {
        if (freq[symbol]) {
            active++;
            if (!lengths[symbol]) fail("active symbol has zero length", histograms);
            kraft += ldexpl(1.0L, -(int)lengths[symbol]);
            if (lengths[symbol] > deepest) deepest = lengths[symbol];
        } else if (lengths[symbol]) {
            fail("absent symbol has nonzero length", histograms);
        }
    }
    if (active <= 2 && deepest != (active ? 1u : 0u))
        fail("empty/single/two-symbol length", histograms);
    if (active >= 2 && fabsl(kraft - 1.0L) > 1e-12L)
        fail("code lengths do not form a complete prefix code", histograms);
    if (require_deep && deepest <= 15) fail("deep-tree fixture", histograms);
    write_bytes("H", 1);
    write_u32(histograms++);
    for (int symbol = 0; symbol < NSYM; symbol++) write_u32(freq[symbol]);
    write_bytes(lengths, sizeof(lengths));
}

static uint32_t next_random(uint32_t *state) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

static void test_histograms(void) {
    uint32_t freq[NSYM] = {0};
    check_histogram(freq, 0);
    freq[255] = UINT32_MAX;
    check_histogram(freq, 0);
    freq[0] = UINT32_MAX;
    check_histogram(freq, 0);
    freq[0] = 1;
    check_histogram(freq, 0);
    for (int symbol = 0; symbol < NSYM; symbol++) freq[symbol] = UINT32_MAX;
    check_histogram(freq, 0);
    memset(freq, 0, sizeof(freq));
    uint64_t previous = 1, current = 1;
    for (int symbol = 0; symbol < 47; symbol++) {
        freq[symbol] = (uint32_t)previous;
        uint64_t next = previous + current;
        previous = current;
        current = next > UINT32_MAX ? UINT32_MAX : next;
    }
    check_histogram(freq, 1);
    /* Every active-count boundary, with ties and permuted symbol positions. */
    for (int active = 0; active <= NSYM; active++) {
        memset(freq, 0, sizeof(freq));
        for (int index = 0; index < active; index++) freq[(index * 73) & 255] = 1;
        check_histogram(freq, 0);
    }
    uint32_t state = 0x6d2b79f5u;
    for (unsigned iteration = 0; iteration < 128; iteration++) {
        memset(freq, 0, sizeof(freq));
        unsigned active = next_random(&state) % (NSYM + 1u);
        for (unsigned index = 0; index < active; index++)
            freq[(index * 73u) & 255u] = next_random(&state) | 1u;
        check_histogram(freq, 0);
    }
}

static void test_stream(size_t size, unsigned pattern, int variant, int off_bytes) {
    size_t token_cap = size + size / 255 + 4;
    uint8_t *tokens = malloc(token_cap);
    uint8_t *decoded = malloc(size + 16);
    size_t encoded_cap = vva_bound(token_cap);
    uint8_t *encoded = malloc(encoded_cap);
    if (!tokens || !decoded || !encoded) fail("allocation", streams);
    size_t prefix = 0, remaining = size - 15;
    tokens[prefix++] = 0xf0; /* A terminal literal-only LZ token. */
    while (remaining >= 255) {
        tokens[prefix++] = 255;
        remaining -= 255;
    }
    tokens[prefix++] = (uint8_t)remaining;
    uint32_t state = 0xa341316cu;
    for (size_t index = 0; index < size; index++) {
        uint8_t value;
        if (pattern == 0) value = 255;
        else if (pattern == 1) value = (index & 1) ? 255 : 0;
        else if (pattern == 2) value = (uint8_t)index;
        else if (pattern == 3) value = (uint8_t)next_random(&state);
        else value = (index % 17) ? 0 : (uint8_t)next_random(&state);
        tokens[prefix + index] = value;
    }
    size_t encoded_size = 0, decoded_size = 0;
    vva_error_t error;
    if (variant == 0)
        error = vva_encode_sequences(tokens, prefix + size, encoded, encoded_cap,
                                     &encoded_size, off_bytes);
    else if (variant == 1)
        error = vva_encode_sequences_v2(tokens, prefix + size, encoded, encoded_cap,
                                        &encoded_size, off_bytes);
    else if (variant == 2)
        error = vva_encode_sequences_compat(tokens, prefix + size, encoded, encoded_cap,
                                            &encoded_size, off_bytes, 1);
    else
        error = vva_encode_sequences_v2_compat(tokens, prefix + size, encoded, encoded_cap,
                                               &encoded_size, off_bytes, 1);
    if (error != VVA_OK || encoded_size < 9) fail("sequence encode", streams);
    uint32_t literal_count = (uint32_t)encoded[0] | ((uint32_t)encoded[1] << 8)
                           | ((uint32_t)encoded[2] << 16) | ((uint32_t)encoded[3] << 24);
    if (literal_count != size || literal_count < 4096)
        fail("estimator-path literal count", streams);
    if (encoded[4] > 4 || (variant >= 2 && encoded[4] == 4))
        fail("literal format", streams);
    formats[encoded[4]]++;
    if (variant & 1)
        error = vva_decode_sequences_v2(encoded, encoded_size, decoded, size + 16,
                                        &decoded_size, decoded);
    else
        error = vva_decode_sequences(encoded, encoded_size, decoded, size + 16,
                                     &decoded_size, decoded);
    if (error != VVA_OK || decoded_size != size ||
        memcmp(decoded, tokens + prefix, size)) fail("sequence roundtrip", streams);
    write_bytes("S", 1);
    write_u32(streams++);
    write_u32((uint32_t)size);
    write_u32(pattern);
    write_u32((uint32_t)variant);
    write_u32((uint32_t)off_bytes);
    write_u32((uint32_t)encoded_size);
    write_bytes(encoded, encoded_size);
    free(encoded);
    free(decoded);
    free(tokens);
}

int main(void) {
#ifdef _WIN32
    if (_setmode(_fileno(stdout), _O_BINARY) < 0) fail("binary stdout mode", 0);
#endif
    test_histograms();
    static const size_t sizes[] = {4096, 4097, 8192, 65536};
    for (unsigned index = 0; index < sizeof(sizes) / sizeof(sizes[0]); index++)
        for (unsigned pattern = 0; pattern < 5; pattern++)
            for (int variant = 0; variant < 4; variant++)
                for (int off_bytes = 2; off_bytes <= 3; off_bytes++)
                    test_stream(sizes[index], pattern, variant, off_bytes);
    if (!formats[0] || !formats[1] || !formats[3] || !formats[4])
        fail("raw/ANS4/Huffman/Huffman4 literal coverage", streams);
    if (fflush(stdout)) fail("transcript flush", 0);
    fprintf(stderr, "PASS: %u histograms, %u v1/v2 sequence streams; formats %u/%u/%u/%u/%u\n",
            histograms, streams, formats[0], formats[1], formats[2], formats[3], formats[4]);
    return 0;
}
