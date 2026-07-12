/*
 * zuptsdk easy.h — high-level API for drop-in encryption.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Goal: 3 lines of code to encrypt/decrypt anything in any language.
 * No context management, no parameter tuning, secure defaults.
 */
#ifndef ZUPTSDK_EASY_H
#define ZUPTSDK_EASY_H

#include "zuptsdk.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ─── String/buffer encryption (PQ pubkey) ─── */

/** Encrypt with recipient pubkey file path. Returns alloc'd combined
 *  blob (header || ciphertext) ready to store/transmit. */
int zuptsdk_easy_encrypt(const char *recipient_pubkey_path,
                         const uint8_t *plaintext, size_t plaintext_sz,
                         uint8_t **blob_out, size_t *blob_sz);

/** Decrypt blob with recipient privkey file path. */
int zuptsdk_easy_decrypt(const char *recipient_privkey_path,
                         const uint8_t *blob, size_t blob_sz,
                         uint8_t **plaintext_out, size_t *plaintext_sz);

/* ─── Password-based encryption ─── */

/** Encrypt with password (Argon2id, MODERATE preset by default). */
int zuptsdk_easy_encrypt_password(const char *password,
                                  const uint8_t *plaintext, size_t plaintext_sz,
                                  uint8_t **blob_out, size_t *blob_sz);

int zuptsdk_easy_decrypt_password(const char *password,
                                  const uint8_t *blob, size_t blob_sz,
                                  uint8_t **plaintext_out, size_t *plaintext_sz);

/* ─── Field-level encryption (for DB columns, JSON fields) ─── */

/** Encrypt small fields with a 32-byte key. Returns base64-encoded
 *  string (alloc'd, NUL-terminated, free with zuptsdk_free).
 *  Suitable for DB columns, JSON fields, env vars. */
int zuptsdk_easy_encrypt_field(const uint8_t key[32],
                               const char *plaintext,
                               char **b64_out);

int zuptsdk_easy_decrypt_field(const uint8_t key[32],
                               const char *b64_input,
                               char **plaintext_out);

/* ─── File encryption with progress ─── */

typedef void (*zuptsdk_easy_progress_t)(uint64_t bytes_done,
                                         uint64_t bytes_total,
                                         void *userdata);

int zuptsdk_easy_encrypt_file(const char *recipient_pubkey_path,
                              const char *input_path,
                              const char *output_path,
                              zuptsdk_easy_progress_t cb, void *userdata);

int zuptsdk_easy_decrypt_file(const char *recipient_privkey_path,
                              const char *input_path,
                              const char *output_path,
                              zuptsdk_easy_progress_t cb, void *userdata);

/* ─── Keypair generation ─── */

/** Generate keypair and save to two paths. Convenience wrapper. */
int zuptsdk_easy_keygen(const char *pubkey_out_path,
                        const char *privkey_out_path);

/** Derive a deterministic 32-byte key from a password via Argon2id.
 *  For field encryption, derive key once at startup, reuse for many fields. */
int zuptsdk_easy_derive_key(const char *password,
                            const uint8_t salt[16],
                            uint8_t key_out[32]);

/* ─── Random salt generation ─── */
int zuptsdk_easy_random_salt(uint8_t out[16]);

#ifdef __cplusplus
}
#endif

#endif
