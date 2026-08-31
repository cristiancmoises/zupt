/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2025-2026 Cristian Cezar Moisés
 *
 * Build a minimal, structurally valid plaintext archive with an arbitrary
 * index path.  This is test infrastructure for extraction-path policy: unlike
 * byte mutation, the resulting index checksum and archive-integrity trailer
 * are valid, so a rejection necessarily reaches the path validation code.
 */
#include "zupt.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int put_u8(FILE *stream, uint8_t value) {
    return fputc(value, stream) == EOF ? -1 : 0;
}

static int put_u16le(FILE *stream, uint16_t value) {
    return put_u8(stream, (uint8_t)value) ||
           put_u8(stream, (uint8_t)(value >> 8)) ? -1 : 0;
}

static size_t put_u32le(uint8_t *out, uint32_t value) {
    for (size_t i = 0; i < 4; i++) out[i] = (uint8_t)(value >> (i * 8));
    return 4;
}

static size_t put_u64le(uint8_t *out, uint64_t value) {
    for (size_t i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (i * 8));
    return 8;
}

static size_t put_varint(uint8_t *out, uint64_t value) {
    size_t count = 0;
    while (value >= 0x80) {
        out[count++] = (uint8_t)(value | 0x80);
        value >>= 7;
    }
    out[count++] = (uint8_t)value;
    return count;
}

static int write_block(FILE *stream, uint8_t type, const uint8_t *payload,
                       size_t payload_size, uint64_t unpacked_size,
                       uint64_t checksum) {
    uint8_t varint[10];
    size_t varint_size;
    if (put_u8(stream, ZUPT_BLOCK_MAGIC_0) ||
        put_u8(stream, ZUPT_BLOCK_MAGIC_1) || put_u8(stream, type) ||
        put_u16le(stream, ZUPT_CODEC_STORE) || put_u16le(stream, 0))
        return -1;
    varint_size = put_varint(varint, unpacked_size);
    if (fwrite(varint, 1, varint_size, stream) != varint_size) return -1;
    varint_size = put_varint(varint, payload_size);
    if (fwrite(varint, 1, varint_size, stream) != varint_size) return -1;
    uint8_t checksum_bytes[8];
    put_u64le(checksum_bytes, checksum);
    if (fwrite(checksum_bytes, 1, sizeof(checksum_bytes), stream) !=
        sizeof(checksum_bytes))
        return -1;
    return payload_size == 0 ||
           fwrite(payload, 1, payload_size, stream) == payload_size ? 0 : -1;
}

int main(int argc, char **argv) {
    static const uint8_t content[] = "fixture content\n";
    const char *entry = argc == 3 && strncmp(argv[2], "--entry=", 8) == 0
        ? argv[2] + 8 : NULL;
    if (!entry || argv[1][0] == '\0' || entry[0] == '\0' ||
        strlen(entry) >= ZUPT_MAX_PATH) {
        fprintf(stderr, "usage: %s ARCHIVE --entry=ENTRY_PATH\n", argv[0]);
        return 2;
    }

    FILE *stream = fopen(argv[1], "wb");
    if (!stream) return 1;

    zupt_archive_header_t header;
    memset(&header, 0, sizeof(header));
    const uint8_t magic[6] = { ZUPT_MAGIC_0, ZUPT_MAGIC_1, ZUPT_MAGIC_2,
                               ZUPT_MAGIC_3, ZUPT_MAGIC_4, ZUPT_MAGIC_5 };
    memcpy(header.magic, magic, sizeof(magic));
    header.version_major = ZUPT_FORMAT_MAJOR;
    header.version_minor = ZUPT_FORMAT_MINOR;
    uint8_t serialized_header[ZUPT_ARCHIVE_HEADER_SIZE] = {0};
    memcpy(serialized_header, header.magic, sizeof(header.magic));
    serialized_header[6] = header.version_major;
    serialized_header[7] = header.version_minor;
    put_u32le(serialized_header + 8, header.global_flags);
    put_u64le(serialized_header + 12, header.creation_time);
    memcpy(serialized_header + 20, header.archive_id, sizeof(header.archive_id));
    put_u64le(serialized_header + 36, header.encryption_header_off);
    put_u64le(serialized_header + 44, header.comment_offset);
    memcpy(serialized_header + 52, header.reserved, sizeof(header.reserved));
    if (fwrite(serialized_header, 1, sizeof(serialized_header), stream) !=
        sizeof(serialized_header)) goto fail;

    const size_t content_size = sizeof(content) - 1;
    uint64_t content_hash = zupt_xxh64(content, content_size, 0);
    uint64_t data_offset = (uint64_t)ftell(stream);
    if (write_block(stream, ZUPT_BLOCK_DATA, content, content_size,
                    content_size, content_hash) != 0)
        goto fail;

    uint8_t index[ZUPT_MAX_PATH + 128];
    size_t index_size = 0;
    size_t path_size = strlen(entry);
    index_size += put_varint(index + index_size, 1);
    index_size += put_varint(index + index_size, path_size);
    memcpy(index + index_size, entry, path_size);
    index_size += path_size;
    index_size += put_u64le(index + index_size, content_size);
    index_size += put_u64le(index + index_size, content_size);
    index_size += put_u64le(index + index_size, 0);
    index_size += put_u64le(index + index_size, content_hash);
    index_size += put_u64le(index + index_size, data_offset);
    index_size += put_varint(index + index_size, 1);
    index_size += put_u32le(index + index_size, 0600);

    uint64_t index_offset = (uint64_t)ftell(stream);
    if (write_block(stream, ZUPT_BLOCK_INDEX, index, index_size, index_size,
                    zupt_xxh64(index, index_size, 0)) != 0)
        goto fail;

    zupt_footer_t footer;
    memset(&footer, 0, sizeof(footer));
    footer.index_offset = index_offset;
    footer.total_blocks = 1;
    footer.archive_checksum = (uint64_t)ftell(stream);
    memcpy(footer.footer_magic, "ZEND", 4);
    footer.footer_version = 1;
    uint8_t serialized_footer[ZUPT_FOOTER_SIZE] = {0};
    put_u64le(serialized_footer, footer.index_offset);
    put_u64le(serialized_footer + 8, footer.total_blocks);
    put_u64le(serialized_footer + 16, footer.archive_checksum);
    memcpy(serialized_footer + 24, footer.footer_magic,
           sizeof(footer.footer_magic));
    put_u32le(serialized_footer + 28, footer.footer_version);
    if (fwrite(serialized_footer, 1, sizeof(serialized_footer), stream) !=
        sizeof(serialized_footer)) goto fail;

    uint8_t mac_input[ZUPT_AIT_MAC_INPUT_LEN];
    uint8_t trailer[ZUPT_AIT_SIZE];
    memcpy(mac_input, serialized_header, sizeof(serialized_header));
    memcpy(mac_input + sizeof(serialized_header), serialized_footer, 24);
    memset(trailer, 0, sizeof(trailer));
    put_u64le(trailer, zupt_xxh64(mac_input, sizeof(mac_input), 0));
    if (fwrite(trailer, sizeof(trailer), 1, stream) != 1 || fclose(stream) != 0)
        return 1;
    return 0;

fail:
    fclose(stream);
    return 1;
}
