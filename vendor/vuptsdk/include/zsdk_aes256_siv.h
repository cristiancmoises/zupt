/*
 * AES-256-SIV (RFC 5297) via OpenSSL EVP
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Provides nonce-misuse-resistant AEAD via SIV mode (S2V + CTR).
 * Uses OpenSSL's audited implementation. Note: SIV uses a 64-byte key
 * (two 32-byte halves) rather than a 32-byte key.
 */
#ifndef ZSDK_AES256_SIV_H
#define ZSDK_AES256_SIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define ZSDK_AES256_SIV_KEYBYTES   64   /* AES-256-SIV uses double key */
#define ZSDK_AES256_SIV_NONCEBYTES 16   /* Optional, can be variable */
#define ZSDK_AES256_SIV_TAGBYTES   16

void zsdk_aes256_siv_encrypt(uint8_t *out,
                             const uint8_t *plaintext, size_t pt_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t key[64],
                             const uint8_t nonce[16]);

int zsdk_aes256_siv_decrypt(uint8_t *out,
                            const uint8_t *ciphertext, size_t ct_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t key[64],
                            const uint8_t nonce[16]);


#ifdef __cplusplus
}
#endif
#endif
