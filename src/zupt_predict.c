/*
 * ZUPT 0.4 - Byte Prediction Preprocessor
 *
 * This is the highest-ROI compression improvement: a reversible transform
 * that captures order-1 (256-context) byte-pair correlations.
 *
 * Algorithm:
 *   1. Build prediction table: for each byte c, find the most common
 *      byte that follows c in the input data.
 *   2. Transform: output[i] = input[i] XOR prediction[input[i-1]]
 *   3. The most common byte after each context becomes 0x00, which
 *      compresses extremely well with Huffman/LZ coding.
 *
 * On decompression: reverse the XOR using the stored prediction table.
 *
 * The prediction table (256 bytes) is stored in the compressed block.
 * Total overhead: 256 bytes per block. For 128KB+ blocks, this is <0.2%.
 *
 * Impact on LZ matching: only the first byte of each match boundary is
 * affected. For matches of length 4+, 75-99% of match bytes are preserved.
 * The entropy improvement on literal bytes more than compensates.
 */

#include "zupt.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* Build a 256-byte prediction table from input data.
 * prediction[c] = the byte value most likely to follow byte c. */
void zupt_predict_build(const uint8_t *data, size_t len, uint8_t prediction[256]) {
    /* Count successor frequencies: count[prev][next] */
    /* Use 16-bit counters to save memory (256*256*2 = 128KB) */
    uint16_t *counts = (uint16_t *)calloc(256 * 256, sizeof(uint16_t));
    if (!counts) {
        memset(prediction, 0, 256);
        return;
    }

    uint8_t prev = 0;
    for (size_t i = 0; i < len; i++) {
        uint16_t *row = counts + (size_t)prev * 256;
        if (row[data[i]] < 65535) row[data[i]]++;
        prev = data[i];
    }

    /* For each context byte, find the most common successor */
    for (int c = 0; c < 256; c++) {
        const uint16_t *row = counts + (size_t)c * 256;
        uint16_t best_count = 0;
        uint8_t best_byte = 0;
        for (int b = 0; b < 256; b++) {
            if (row[b] > best_count) {
                best_count = row[b];
                best_byte = (uint8_t)b;
            }
        }
        prediction[c] = best_byte;
    }

    free(counts);
}

/* Apply the prediction transform (forward).
 * Each byte is XORed with the prediction for the previous byte.
 * The most common successor becomes 0x00, improving entropy. */
void zupt_predict_encode(const uint8_t *input, uint8_t *output, size_t len,
                         const uint8_t prediction[256]) {
    uint8_t prev = 0;
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ prediction[prev];
        prev = input[i];  /* Use ORIGINAL byte as next context */
    }
}

/* Reverse the prediction transform (inverse).
 * Recovers the original byte, then uses it as the next context. */
void zupt_predict_decode(const uint8_t *input, uint8_t *output, size_t len,
                         const uint8_t prediction[256]) {
    uint8_t prev = 0;
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ prediction[prev];
        prev = output[i];  /* Use RECOVERED byte as next context */
    }
}

/* Test whether the prediction transform would help.
 * Returns estimated entropy reduction (0.0 = no help, 1.0 = huge help).
 * Quick test on first 4KB of data. */
float zupt_predict_benefit(const uint8_t *data, size_t len) {
    if (len < 256) return 0.0f;
    size_t test_len = len < 4096 ? len : 4096;

    /* Compute byte entropy of original */
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < test_len; i++) freq[data[i]]++;
    float h_orig = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        float p = (float)freq[i] / (float)test_len;
        h_orig -= p * log2f(p);
    }

    /* Build prediction table and transform */
    uint8_t pred[256];
    zupt_predict_build(data, test_len, pred);

    uint8_t *transformed = (uint8_t *)malloc(test_len);
    if (!transformed) return 0.0f;
    zupt_predict_encode(data, transformed, test_len, pred);

    /* Compute byte entropy of transformed */
    memset(freq, 0, sizeof(freq));
    for (size_t i = 0; i < test_len; i++) freq[transformed[i]]++;
    float h_trans = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        float p = (float)freq[i] / (float)test_len;
        h_trans -= p * log2f(p);
    }

    free(transformed);

    if (h_orig < 0.1f) return 0.0f;  /* Already near-zero entropy */
    return (h_orig - h_trans) / h_orig;  /* Fraction of entropy removed */
}
