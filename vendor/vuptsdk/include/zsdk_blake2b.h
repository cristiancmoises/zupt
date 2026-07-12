/*
 * BLAKE2b (RFC 7693)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef ZSDK_BLAKE2B_H
#define ZSDK_BLAKE2B_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define ZSDK_BLAKE2B_BLOCKBYTES 128
#define ZSDK_BLAKE2B_OUTBYTES   64

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[ZSDK_BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
} zsdk_blake2b_state;

int  zsdk_blake2b_init(zsdk_blake2b_state *s, size_t outlen);
int  zsdk_blake2b_init_key(zsdk_blake2b_state *s, size_t outlen,
                           const void *key, size_t keylen);
int  zsdk_blake2b_update(zsdk_blake2b_state *s, const void *in, size_t inlen);
int  zsdk_blake2b_final(zsdk_blake2b_state *s, void *out, size_t outlen);

/* One-shot. */
int  zsdk_blake2b(void *out, size_t outlen,
                  const void *in, size_t inlen,
                  const void *key, size_t keylen);

/* Argon2's "long hash" H' producing arbitrary length output. */
int  zsdk_blake2b_long(uint8_t *out, size_t outlen,
                       const uint8_t *in, size_t inlen);


#ifdef __cplusplus
}
#endif
#endif
