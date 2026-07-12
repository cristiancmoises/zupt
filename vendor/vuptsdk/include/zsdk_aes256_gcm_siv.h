/*
 * AES-256-GCM-SIV (RFC 8452)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Nonce-misuse-resistant AEAD. Nonce reuse degrades to deterministic
 * encryption (same plaintext+key+nonce -> same ciphertext) rather than
 * the catastrophic XOR-of-plaintexts of GCM/CTR.
 */
#ifndef ZSDK_AES256_GCM_SIV_H
#define ZSDK_AES256_GCM_SIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define ZSDK_AES256_GCM_SIV_KEYBYTES   32
#define ZSDK_AES256_GCM_SIV_NONCEBYTES 12
#define ZSDK_AES256_GCM_SIV_TAGBYTES   16

void zsdk_aes256_gcm_siv_encrypt(uint8_t *out,
                                 const uint8_t *plaintext, size_t pt_len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t key[32],
                                 const uint8_t nonce[12]);

int zsdk_aes256_gcm_siv_decrypt(uint8_t *out,
                                const uint8_t *ciphertext, size_t ct_len,
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t key[32],
                                const uint8_t nonce[12]);


#ifdef __cplusplus
}
#endif
#endif
