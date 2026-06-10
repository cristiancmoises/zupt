/*
 * libpqvaptvupt — post-quantum sealed-box encryption.
 *
 * A minimal, libsodium-style sealed-box API backed by a real hybrid
 * post-quantum KEM (ML-KEM-768 + X25519) plus AES-256-CTR + HMAC-SHA256
 * Encrypt-then-MAC. The construction matches Zupt v2.1.5+.
 *
 * Three functions. No state. No streams.
 *
 *   pqvv_keygen(pk, sk)                                    — one-time
 *   pqvv_seal(pk,   pt, pt_len, &ct, &ct_len)              — encrypt
 *   pqvv_open(sk,   ct, ct_len, &pt, &pt_len)              — decrypt
 *
 * Identical ergonomic to libsodium's crypto_box_seal / crypto_box_seal_open,
 * but with PQ KEM beneath. Migration from libsodium is a sed:
 *
 *   crypto_box_keypair    → pqvv_keygen
 *   crypto_box_seal       → pqvv_seal
 *   crypto_box_seal_open  → pqvv_open
 *
 * Copyright (c) 2026 Cristian Cezar Moisés.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Commercial license: sac@securityops.co
 *
 * Vendored cryptographic primitives:
 *   - ML-KEM-768  (FIPS 203)               from Zupt v2.1.5 src/zupt_mlkem.c
 *   - X25519      (RFC 7748)               from Zupt v2.1.5 src/zupt_x25519.c
 *   - SHA-3 / SHAKE-128 / SHAKE-256        from Zupt v2.1.5 src/zupt_keccak.c
 *   - SHA-256     (FIPS 180-4)             from Zupt v2.1.5 src/zupt_sha256.c
 *   - AES-256-CTR (NIST SP 800-38A)        from Zupt v2.1.5 src/zupt_aes256.c
 *   - HMAC-SHA256 (RFC 2104)               from Zupt v2.1.5 src/zupt_crypto.c
 *   - OS CSPRNG                            from Zupt v2.1.5 src/zupt_crypto.c
 *
 * All primitives are verified against NIST/RFC test vectors in tests/.
 */
#ifndef LIBPQVAPTVUPT_H
#define LIBPQVAPTVUPT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────────────────────────────────────────────────────
 * Version
 * ──────────────────────────────────────────────────────────────────── */
#define PQVV_VERSION_MAJOR  0
#define PQVV_VERSION_MINOR  6
#define PQVV_VERSION_PATCH  0
#define PQVV_VERSION_STRING "0.6.0"

/* ─────────────────────────────────────────────────────────────────────
 * Sizes (compile-time constants for callers that want to stack-allocate)
 * ──────────────────────────────────────────────────────────────────── */
#define PQVV_PUBLICKEYBYTES   1216  /* ML-KEM-768 pk (1184) + X25519 pk (32) */
#define PQVV_SECRETKEYBYTES   2432  /* ML-KEM-768 sk (2400) + X25519 sk (32) */
#define PQVV_OVERHEAD         1184  /* per-message overhead (KEM ct + ephemeral pk + nonce + MAC) */
                                    /*   ML-KEM-768 ct (1088) + ephem X25519 pk (32) + nonce (16) + MAC (32) + magic (16) */

/* Return codes. Zero on success; negative on error. */
typedef enum {
    PQVV_OK                = 0,
    PQVV_ERR_NULL          = -1,  /* NULL pointer in arguments */
    PQVV_ERR_RANGE         = -2,  /* size out of range */
    PQVV_ERR_AUTH          = -3,  /* MAC verification failed (tampered / wrong key) */
    PQVV_ERR_CORRUPT       = -4,  /* ciphertext malformed */
    PQVV_ERR_NOMEM         = -5,  /* allocation failed */
    PQVV_ERR_INTERNAL      = -6,  /* unexpected internal error */
} pqvv_error_t;

/* ─────────────────────────────────────────────────────────────────────
 * API
 * ──────────────────────────────────────────────────────────────────── */

/**
 * Library version string. Same as PQVV_VERSION_STRING.
 */
const char *pqvv_version(void);

/**
 * Generate a fresh hybrid keypair. Public key is PQVV_PUBLICKEYBYTES bytes,
 * secret key is PQVV_SECRETKEYBYTES bytes; both layouts are opaque.
 *
 * Uses the OS CSPRNG for all randomness. Aborts the process if no CSPRNG
 * is available (no fallback — predictable keys would destroy security).
 *
 * @return PQVV_OK on success, PQVV_ERR_NULL if either pointer is NULL.
 */
int pqvv_keygen(uint8_t pk[PQVV_PUBLICKEYBYTES], uint8_t sk[PQVV_SECRETKEYBYTES]);

/**
 * Seal plaintext to a recipient public key. Output is freshly malloc'd
 * and the caller owns it (free with free()).
 *
 * Construction (in order, all binary):
 *   magic       16 bytes "pqvaptvupt-v1\0\0\0"
 *   kem_ct      1088 bytes ML-KEM-768 ciphertext (encapsulation)
 *   ephem_pk    32 bytes  ephemeral X25519 public key
 *   nonce       16 bytes  random
 *   mac         32 bytes  HMAC-SHA256 over (magic||kem_ct||ephem_pk||nonce||body)
 *   body        AES-256-CTR(plaintext)  with key derived as
 *                  HKDF-SHA256-Extract(salt=nonce, IKM=ml_kem_ss || x25519_ss)
 *                  HKDF-SHA256-Expand(info="pqvv-seal-v1", L=64) → enc_key||mac_key
 *
 * The recipient's pk encapsulates both ML-KEM-768 ss and X25519 ss; the
 * sender contributes its own X25519 ephemeral. Combined entropy goes
 * through HKDF; if either KEM is broken later, the other still protects.
 *
 * @param pk        recipient's public key
 * @param pt        plaintext bytes
 * @param pt_len    plaintext length
 * @param out       set to pointer to ciphertext buffer (caller frees)
 * @param out_len   set to ciphertext length
 * @return PQVV_OK on success, negative on error.
 */
int pqvv_seal(const uint8_t pk[PQVV_PUBLICKEYBYTES],
              const uint8_t *pt, size_t pt_len,
              uint8_t **out, size_t *out_len);

/**
 * Open a sealed message. Verifies the MAC before doing any decryption.
 * Output is freshly malloc'd and the caller owns it (free with free()).
 *
 * @param sk        recipient's secret key
 * @param ct        ciphertext bytes from pqvv_seal
 * @param ct_len    ciphertext length
 * @param out       set to pointer to plaintext buffer (caller frees)
 * @param out_len   set to plaintext length
 * @return PQVV_OK on success, PQVV_ERR_AUTH if MAC fails, PQVV_ERR_CORRUPT
 *         if ciphertext shape is invalid, negative on other error.
 */
int pqvv_open(const uint8_t sk[PQVV_SECRETKEYBYTES],
              const uint8_t *ct, size_t ct_len,
              uint8_t **out, size_t *out_len);

/* ─────────────────────────────────────────────────────────────────────
 * Primitives (exported for testing against NIST/RFC vectors)
 *
 * Not the recommended user-facing API — use pqvv_seal / pqvv_open. These
 * are exported so the test suite can verify each primitive in isolation
 * against the official test vectors.
 * ──────────────────────────────────────────────────────────────────── */

/**
 * SHA-256 (FIPS 180-4). Computes the 32-byte digest of `len` bytes.
 */
void pqvv_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/**
 * HMAC-SHA-256 (RFC 2104).
 */
void pqvv_hmac_sha256(const uint8_t *key, size_t klen,
                      const uint8_t *msg, size_t mlen,
                      uint8_t out[32]);

/**
 * Fill `buf` with `len` cryptographically-strong random bytes from the
 * OS CSPRNG. Aborts the process on failure.
 */
void pqvv_random_bytes(uint8_t *buf, size_t len);

/**
 * Constant-time memory equality. Returns 1 if equal, 0 otherwise.
 * Use for comparing secrets, MACs, etc. Never use memcmp.
 */
int pqvv_ct_memeq(const void *a, const void *b, size_t n);

/**
 * Zero a memory region in a way the compiler cannot optimize away.
 */
void pqvv_memzero(void *p, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* LIBPQVAPTVUPT_H */
