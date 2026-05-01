/*
 * XChaCha20-Poly1305 AEAD
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implements:
 *   - ChaCha20 (RFC 8439)
 *   - HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2)
 *   - XChaCha20 (draft-irtf-cfrg-xchacha-03 §2.3)
 *   - Poly1305 (RFC 8439 §2.5)
 *   - XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha-03 §2.4)
 *
 * Constant-time implementation: no secret-dependent branches or memory
 * accesses. Verified against RFC 8439 test vectors and Wycheproof corpus.
 */

#ifndef ZUPTSDK_XCHACHA20_POLY1305_H
#define ZUPTSDK_XCHACHA20_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZSDK_XCHACHA20_POLY1305_KEYBYTES   32
#define ZSDK_XCHACHA20_POLY1305_NONCEBYTES 24
#define ZSDK_XCHACHA20_POLY1305_TAGBYTES   16

/* Encrypt: ciphertext_len = plaintext_len; tag is 16 bytes appended.
 * out buffer size must be >= plaintext_len + 16. */
void zsdk_xchacha20_poly1305_encrypt(
    uint8_t       *out,        /* [out] ciphertext || tag */
    const uint8_t *plaintext,
    size_t         plaintext_len,
    const uint8_t *aad,
    size_t         aad_len,
    const uint8_t  key[32],
    const uint8_t  nonce[24]);

/* Decrypt: returns 0 on success, -1 on tag mismatch (out untouched).
 * out buffer size must be >= ciphertext_len - 16. */
int zsdk_xchacha20_poly1305_decrypt(
    uint8_t       *out,        /* [out] plaintext */
    const uint8_t *ciphertext, /* ciphertext || tag */
    size_t         ciphertext_len, /* includes 16-byte tag */
    const uint8_t *aad,
    size_t         aad_len,
    const uint8_t  key[32],
    const uint8_t  nonce[24]);

#ifdef __cplusplus
}
#endif

#endif
