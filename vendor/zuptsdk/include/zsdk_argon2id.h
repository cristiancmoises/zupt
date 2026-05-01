/*
 * Argon2id (RFC 9106)
 * Copyright (c) 2026 Cristian Cezar Moisés
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Memory-hard password hashing function. Reference implementation
 * (single-lane focus), verified against RFC 9106 §5 test vectors.
 */
#ifndef ZSDK_ARGON2ID_H
#define ZSDK_ARGON2ID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Returns 0 on success, -1 on parameter validation failure or alloc fail.
 *
 *   passwd, passwd_len   the password (any length)
 *   salt, salt_len       random salt (>= 8 bytes recommended; >= 16 standard)
 *   memory_kib           memory cost in KiB (>= 8 * lanes; we require >= 19456)
 *   iterations           time cost (>= 1; we require >= 2)
 *   lanes                parallelism (>= 1, <= 4 here)
 *   out, out_len         output buffer (>= 4 bytes; typically 32)
 */
int zsdk_argon2id(const uint8_t *passwd, size_t passwd_len,
                  const uint8_t *salt,   size_t salt_len,
                  uint32_t       memory_kib,
                  uint32_t       iterations,
                  uint32_t       lanes,
                  uint8_t       *out,    size_t out_len);


#ifdef __cplusplus
}
#endif
#endif
