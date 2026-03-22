# Zupt Archive Format Specification v1.4

**Status: FROZEN at v1.0.0.** Future format changes require v2.0 (new magic bytes).

## Overview

A `.zupt` archive is a sequential byte stream:

```
[Archive Header (64B)] [Encryption Header Block?] [Data Blocks...] [Index Block] [Footer (32B)]
```

All multi-byte integers are **little-endian**. All variable-length integers use unsigned LEB128 (varint).

## Archive Header (64 bytes, offset 0)

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 6 | magic | `5A 55 50 54 1A 00` ("ZUPT\x1a\0") |
| 6 | 1 | version_major | 1 |
| 7 | 1 | version_minor | 4 |
| 8 | 4 | global_flags | Bitfield (LE uint32) |
| 12 | 8 | creation_time | Nanoseconds since epoch (LE uint64) |
| 20 | 16 | archive_id | Random UUID |
| 36 | 8 | encryption_header_off | Offset to encryption header block (0 if unencrypted) |
| 44 | 8 | comment_offset | Reserved (0) |
| 52 | 12 | reserved | Zero-filled |

### Global Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | ENCRYPTED | Archive is encrypted |
| 1 | SOLID | Solid-mode archive |
| 2 | MULTITHREADED | Produced with multi-threaded compression (informational) |
| 3 | PQ_HYBRID | Post-quantum hybrid encryption active |
| 4 | FORMAT_STABLE | Format is frozen (v1.0+) |
| 5 | — | Checksum type: 0 = XXH64 |

## Block Header

Each block starts with:

| Size | Field | Description |
|------|-------|-------------|
| 1 | magic_0 | `0xBB` |
| 1 | magic_1 | `0x01` |
| 1 | block_type | `0x00`=Data, `0x02`=Index, `0x03`=Encryption Header |
| 2 | codec_id | LE uint16. See Codec IDs. |
| 2 | block_flags | LE uint16. Bit 0 = encrypted. |
| varint | uncompressed_size | Original data size |
| varint | compressed_size | Payload size (= compressed, or = uncompressed if STORE) |
| 8 | checksum | XXH64 of uncompressed data (LE uint64) |
| ... | payload | `compressed_size` bytes |

### Codec IDs

| ID | Name | Description |
|----|------|-------------|
| `0x0000` | STORE | No compression |
| `0x0008` | Zupt-LZ | LZ77, 64KB window |
| `0x0009` | Zupt-LZH | LZ77 + Huffman, 1MB window |
| `0x000A` | Zupt-LZHP | LZ77 + Huffman + byte prediction (default) |

### Zupt-LZHP Payload Layout

```
[1B] prediction_flag (0x00=off, 0x01=on)
  if 0x01: [256B] prediction table
[...] LZH compressed data
```

## Encryption Header Block

Located at `encryption_header_off` from the archive header.

### PBKDF2 Mode (enc_type = 0x01)

| Size | Field |
|------|-------|
| 1 | enc_type = `0x01` |
| 32 | salt |
| 16 | base_nonce |
| 4 | iteration_count (LE uint32) |

### PQ Hybrid Mode (enc_type = 0x02)

| Size | Field |
|------|-------|
| 1 | enc_type = `0x02` |
| 1088 | ML-KEM-768 ciphertext |
| 32 | Ephemeral X25519 public key |
| 16 | base_nonce |

### Legacy Mode (no enc_type prefix, v0.5 archives)

| Size | Field |
|------|-------|
| 32 | salt |
| 16 | nonce |
| 4 | iteration_count |

Detection: if first byte is not `0x01` or `0x02` and payload size is 52, treat as legacy.

## Encrypted Block Payload

Each encrypted block payload contains:

```
[16B] per-block nonce (base_nonce XOR block_sequence_LE8)
[...] AES-256-CTR ciphertext
[32B] HMAC-SHA256(mac_key, nonce ‖ ciphertext)
```

**Decrypt order:** Verify HMAC first (Encrypt-then-MAC), then decrypt.

## Central Index Block

Block type `0x02`. Codec: always Zupt-LZH (compressed). Contains:

```
[varint] file_count
For each file:
  [varint] path_length
  [bytes]  path (UTF-8)
  [8B]     uncompressed_size (LE)
  [8B]     compressed_size (LE)
  [8B]     modification_time (LE, nanoseconds)
  [8B]     content_hash (LE, chained XXH64)
  [8B]     first_block_offset (LE)
  [4B]     block_count (LE)
  [4B]     attributes (LE)
```

If archive is encrypted, the entire index block payload is encrypted.

## Footer (32 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | index_offset (LE uint64) |
| 8 | 8 | total_blocks (LE uint64) |
| 16 | 8 | archive_checksum (LE uint64, XXH64 of all block checksums) |
| 24 | 4 | footer_magic = `"ZEND"` |
| 28 | 4 | footer_version (LE uint32) |

## Backward Compatibility

| Reader | Reads |
|--------|-------|
| v1.0+ | All v0.3+ archives |
| v0.6 | v0.3–v1.3 (rejects v1.4 PQ archives with clean error) |
| v0.5 | v0.3–v1.2 |
