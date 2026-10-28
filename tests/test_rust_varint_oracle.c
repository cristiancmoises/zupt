/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2026 Cristian Cezar Moisés
 * Exercise the actual buffer and FILE APIs in src/zupt_format.c.
 * Test protocol: two-byte little-endian length, followed by at most 32 bytes.
 */
#include "zupt.h"
#include <inttypes.h>
#include <string.h>

extern int zupt_encode_varint(uint8_t *buffer, uint64_t value);
extern int zupt_decode_varint(const uint8_t *buffer, size_t length, uint64_t *value);

int main(void) {
    for (;;) {
        int lo = fgetc(stdin);
        if (lo == EOF) return ferror(stdin) ? 2 : (fflush(stdout) == 0 ? 0 : 2);
        int hi = fgetc(stdin);
        if (hi == EOF) return 2;
        size_t length = (size_t)(unsigned int)lo | ((size_t)(unsigned int)hi << 8);
        uint8_t input[32], encoded[10], streamed[10];
        if (length > sizeof(input) || fread(input, 1, length, stdin) != length) return 2;
        uint64_t value = 0, stream_value = 0;
        int count = zupt_decode_varint(input, length, &value);
        FILE *stream = tmpfile();
        if (!stream) return 2;
        if (fwrite(input, 1, length, stream) != length || fseek(stream, 0, SEEK_SET) != 0) {
            fclose(stream);
            return 2;
        }
        int stream_count = zupt_read_varint(stream, &stream_value);
        long position = ftell(stream);
        if (fclose(stream) != 0) return 2;
        if ((count < 0) != (stream_count < 0)) return 2;
        if (count < 0) {
            if (puts("ERR") == EOF) return 2;
            continue;
        }
        if (stream_count != count || position != count || value != stream_value) return 2;
        int encoded_count = zupt_encode_varint(encoded, value);
        if (encoded_count != count || memcmp(encoded, input, (size_t)count) != 0) return 2;
        stream = tmpfile();
        if (!stream) return 2;
        int written = zupt_write_varint(stream, value);
        int bad = written != count || fseek(stream, 0, SEEK_SET) != 0;
        if (!bad) bad = fread(streamed, 1, (size_t)count, stream) != (size_t)count;
        if (!bad) bad = memcmp(streamed, encoded, (size_t)count) != 0;
        if (fclose(stream) != 0 || bad) return 2;
        if (printf("%d %" PRIu64 "\n", count, value) < 0) return 2;
    }
}
