/*
 * HKDF-SHA3-256 (RFC 5869, with SHA3-256 as the hash)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * SHA3-256 is preferred over SHA-256 here because Keccak's sponge
 * construction has stronger structural properties (no length-extension,
 * indifferentiable from a random oracle in the standard model).
 */
#ifndef ZSDK_HKDF_H
#define ZSDK_HKDF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define ZSDK_HKDF_HASHLEN 32  /* SHA3-256 output size */

/* HKDF-Extract: PRK = HMAC-SHA3-256(salt, IKM) */
void zsdk_hkdf_extract(uint8_t        prk[32],
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm,  size_t ikm_len);

/* HKDF-Expand: produces `out_len` bytes (out_len <= 255 * 32). */
int zsdk_hkdf_expand(uint8_t       *out, size_t out_len,
                     const uint8_t  prk[32],
                     const uint8_t *info, size_t info_len);

/* Convenience: extract+expand in one call. */
int zsdk_hkdf(uint8_t       *out,  size_t out_len,
              const uint8_t *salt, size_t salt_len,
              const uint8_t *ikm,  size_t ikm_len,
              const uint8_t *info, size_t info_len);


#ifdef __cplusplus
}
#endif
#endif
